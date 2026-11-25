package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unsafe"
)

// The ioctl structures have the kernel's sizes (amd64, arm64).
func TestABISizes(t *testing.T) {
	if n := unsafe.Sizeof(nvmePassthru{}); n != 72 {
		t.Errorf("nvme_passthru_cmd %d, want 72", n)
	}
	if n := unsafe.Sizeof(sgIOHdr{}); n != 88 {
		t.Errorf("sg_io_hdr %d, want 88", n)
	}
	if off := unsafe.Offsetof(nvmePassthru{}.Addr); off != 24 {
		t.Errorf("nvme_passthru_cmd.addr at %d", off)
	}
	if off := unsafe.Offsetof(sgIOHdr{}.Status); off != 64 {
		t.Errorf("sg_io_hdr.status at %d", off)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// nvmeLog is a SMART / Health log with the given critical warning,
// percentage used and media errors.
func nvmeLog(warning, used byte, media uint64) []byte {
	b := make([]byte, 512)
	b[0] = warning
	binary.LittleEndian.PutUint16(b[1:], 273+41) // 41 °C
	b[3], b[4], b[5] = 100, 10, used
	binary.LittleEndian.PutUint64(b[128:], 1234) // power-on hours
	binary.LittleEndian.PutUint64(b[144:], 7)    // unsafe shutdowns
	binary.LittleEndian.PutUint64(b[160:], media)
	binary.LittleEndian.PutUint64(b[176:], 2)
	return b
}

// ataTables are SMART READ DATA and READ THRESHOLDS with attributes
// (id, flags, value, threshold, raw).
func ataTables(attrs ...[5]uint64) (values, thresholds []byte) {
	values, thresholds = make([]byte, 512), make([]byte, 512)
	for i, a := range attrs {
		v, th := values[2+12*i:], thresholds[2+12*i:]
		v[0], th[0] = byte(a[0]), byte(a[0])
		binary.LittleEndian.PutUint16(v[1:], uint16(a[1]))
		v[3], v[4], th[1] = byte(a[2]), byte(a[2]), byte(a[3])
		for j := 0; j < 6; j++ {
			v[5+j] = byte(a[4] >> (8 * j))
		}
	}
	return values, thresholds
}

// statusSense is RETURN STATUS's descriptor sense data with LBA mid and
// high.
func statusSense(mid, high byte) []byte {
	s := make([]byte, 22)
	s[0], s[7] = 0x72, 14
	d := s[8:]
	d[0], d[1], d[9], d[11] = 0x09, 0x0c, mid, high
	return s
}

type fakeDisk struct {
	nvme   map[string][]byte
	ata    map[string][3][]byte
	opened []string
}

func (f *fakeDisk) nvmeSMART(path string) ([]byte, error) {
	f.opened = append(f.opened, path)
	if b, ok := f.nvme[filepath.Base(path)]; ok {
		return b, nil
	}
	return nil, errors.New("no such device")
}

func (f *fakeDisk) ataSMART(path string) ([]byte, []byte, []byte, error) {
	f.opened = append(f.opened, path)
	if b, ok := f.ata[filepath.Base(path)]; ok {
		return b[0], b[1], b[2], nil
	}
	return nil, nil, nil, errors.New("no such device")
}

type fakeBtrfs struct {
	fsids   map[string]string
	paths   map[uint64]string
	stats   map[uint64][5]uint64
	running bool
}

func (f *fakeBtrfs) fsid(mp string) (string, error) {
	if id, ok := f.fsids[mp]; ok {
		return id, nil
	}
	return "", errors.New("not btrfs")
}
func (f *fakeBtrfs) devPath(_ string, id uint64) (string, error) { return f.paths[id], nil }
func (f *fakeBtrfs) devStats(_ string, id uint64) ([5]uint64, error) {
	if v, ok := f.stats[id]; ok {
		return v, nil
	}
	return [5]uint64{}, errors.New("ENODEV")
}
func (f *fakeBtrfs) scrubRunning(string, uint64) (bool, error) { return f.running, nil }

const fsid = "0b9e3a4c-1111-2222-3333-444455556666"

// testHost is a host with an NVMe namespace, a SATA disk, a USB disk, a
// virtio disk with a partition, a loop device and one btrfs (two
// devices) mounted at / and /home (subvolumes).
func testHost(t *testing.T) (*host, *fakeDisk, *fakeBtrfs) {
	t.Helper()
	root := t.TempDir()
	sys := filepath.Join(root, "sys")
	block := filepath.Join(sys, "class", "block")
	devs := filepath.Join(sys, "devices")

	symlink(t, filepath.Join(devs, "pci0000:00", "nvme", "nvme0"), filepath.Join(block, "nvme0n1", "device"))
	write(t, filepath.Join(devs, "pci0000:00", "nvme", "nvme0", "model"), "Fake NVMe SSD 1TB  \n")
	write(t, filepath.Join(devs, "pci0000:00", "nvme", "nvme0", "serial"), "S123\n")
	write(t, filepath.Join(block, "nvme0n1", "size"), "2000000\n")
	write(t, filepath.Join(block, "nvme0n1", "queue", "rotational"), "0\n")
	write(t, filepath.Join(block, "nvme0n1p1", "partition"), "1\n")

	ata := filepath.Join(devs, "pci0000:00", "ata1", "host0", "target0:0:0", "0:0:0:0")
	symlink(t, ata, filepath.Join(block, "sda", "device"))
	write(t, filepath.Join(ata, "vendor"), "ATA\n")
	write(t, filepath.Join(ata, "model"), "Fake SATA SSD\n")
	write(t, filepath.Join(ata, "vpd_pg80"), "\x00\x80\x00\x05SN-42")
	write(t, filepath.Join(block, "sda", "size"), "1000000\n")

	symlink(t, filepath.Join(devs, "pci0000:00", "usb1", "1-1", "host6", "target6:0:0", "6:0:0:0"), filepath.Join(block, "sdb", "device"))
	write(t, filepath.Join(block, "vda", "size"), "100\n")
	write(t, filepath.Join(block, "vda1", "partition"), "1\n")
	write(t, filepath.Join(block, "loop0", "size"), "0\n")
	write(t, filepath.Join(block, "ram0", "size"), "0\n")

	bt := filepath.Join(sys, "fs", "btrfs", fsid)
	write(t, filepath.Join(bt, "label"), "root\n")
	write(t, filepath.Join(bt, "devinfo", "1", "error_stats"), "write_errs 0\nread_errs 3\nflush_errs 0\ncorruption_errs 0\ngeneration_errs 0\n")
	if err := os.MkdirAll(filepath.Join(bt, "devinfo", "2"), 0o755); err != nil { // no error_stats: the ioctl
		t.Fatal(err)
	}

	mountinfo := filepath.Join(root, "mountinfo")
	write(t, mountinfo, strings.Join([]string{
		"22 1 0:21 /@/home /home rw,relatime shared:1 - btrfs /dev/nvme0n1p2 rw,subvol=/@/home",
		"21 1 0:20 /@/root / rw,relatime shared:2 - btrfs /dev/nvme0n1p2 rw,subvol=/@/root",
		"30 21 0:5 / /dev rw - devtmpfs devtmpfs rw",
		"31 21 0:30 / /mnt/with\\040space rw - xfs /dev/sdb1 rw",
	}, "\n")+"\n")

	scrubDir := filepath.Join(root, "btrfs")
	write(t, filepath.Join(scrubDir, "scrub.status."+fsid), "scrub status:1\n"+
		fsid+":1|data_bytes_scrubbed:1000|tree_bytes_scrubbed:24|read_errors:0|csum_errors:1|verify_errors:0|super_errors:0|uncorrectable_errors:0|corrected_errors:1|t_start:1763900000|t_resumed:0|duration:60|canceled:0|finished:1\n"+
		fsid+":2|data_bytes_scrubbed:500|tree_bytes_scrubbed:0|read_errors:0|csum_errors:0|verify_errors:0|super_errors:0|uncorrectable_errors:0|corrected_errors:0|t_start:1763900010|t_resumed:0|duration:70|canceled:0|finished:1\n")

	values, thresholds := ataTables([5]uint64{5, 0x33, 100, 10, 0}, [5]uint64{9, 0x32, 99, 0, 20000}, [5]uint64{194, 0x22, 64, 0, 36})
	disk := &fakeDisk{nvme: map[string][]byte{"nvme0n1": nvmeLog(0, 3, 0)},
		ata: map[string][3][]byte{"sda": {statusSense(0x4F, 0xC2), values, thresholds}}}
	bfs := &fakeBtrfs{fsids: map[string]string{"/": fsid, "/home": fsid}, paths: map[uint64]string{1: "/dev/nvme0n1p2", 2: "/dev/sda1"},
		stats: map[uint64][5]uint64{2: {0, 0, 0, 2, 0}}}
	return &host{sys: sys, dev: "/dev", mountinfo: mountinfo, scrubDir: scrubDir, disk: disk, btrfs: bfs}, disk, bfs
}

func TestDevices(t *testing.T) {
	h, _, _ := testHost(t)
	d := h.devices()
	var names []string
	for _, x := range d {
		names = append(names, x.Name)
	}
	if !slices.Equal(names, []string{"loop0", "nvme0n1", "sda", "sdb", "vda"}) {
		t.Fatalf("devices %v", names)
	}
	byName := map[string]Device{}
	for _, x := range d {
		byName[x.Name] = x
	}
	if n := byName["nvme0n1"]; n.Transport != "nvme" || n.Model != "Fake NVMe SSD 1TB" || n.Serial != "S123" || n.SizeBytes != 2000000*512 || !n.Health {
		t.Errorf("nvme %+v", n)
	}
	if s := byName["sda"]; s.Transport != "sata" || s.Model != "ATA Fake SATA SSD" || s.Serial != "SN-42" || !s.Health {
		t.Errorf("sda %+v", s)
	}
	if u := byName["sdb"]; u.Transport != "usb" || u.Health || !strings.Contains(u.HealthNote, "usb") {
		t.Errorf("sdb %+v", u)
	}
	if v := byName["vda"]; v.Transport != "virtio" || v.Health || v.HealthNote == "" {
		t.Errorf("vda %+v", v)
	}
}

func TestDeviceHealth(t *testing.T) {
	h, disk, _ := testHost(t)
	n, err := h.deviceHealth("nvme0n1")
	if err != nil || n.Verdict != "ok" || n.NVMe == nil || n.NVMe.TemperatureCelsius != 41 || n.NVMe.PowerOnHours != 1234 ||
		n.NVMe.UnsafeShutdowns != 7 || n.NVMe.ErrorLogEntries != 2 || n.Thresholds == nil {
		t.Fatalf("nvme %+v %v", n, err)
	}
	a, err := h.deviceHealth("sda")
	if err != nil || a.Verdict != "ok" || a.ATA == nil || !a.ATA.StatusPassed || len(a.ATA.Attributes) != 3 ||
		*a.ATA.TemperatureCelsius != 36 || *a.ATA.PowerOnHours != 20000 || a.ATA.Attributes[0].Name != "Reallocated_Sector_Ct" ||
		!a.ATA.Attributes[0].PreFailure || a.ATA.Attributes[0].Threshold != 10 {
		t.Fatalf("sata %+v %v", a, err)
	}
	// Refused before any device is opened: a path, a name not listed, a
	// device without a health log.
	disk.opened = nil
	for name, want := range map[string]string{
		"/dev/sda": "not an NVMe namespace", "../sda": "not an NVMe namespace", "sda1": "not an NVMe namespace",
		"nvme1n1": "not on this host", "sdb": "not over usb", "vda": "not an NVMe namespace",
	} {
		if _, err := h.deviceHealth(name); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", name, err, want)
		}
	}
	if len(disk.opened) != 0 {
		t.Errorf("opened %v", disk.opened)
	}
}

func TestNVMeVerdict(t *testing.T) {
	for _, c := range []struct {
		log  []byte
		want string
	}{
		{nvmeLog(0, 3, 0), "ok"},
		{nvmeLog(0x02, 3, 0), "warning"}, // temperature
		{nvmeLog(0, 95, 0), "warning"},
		{nvmeLog(0, 3, 1), "warning"},
		{nvmeLog(0x04, 3, 0), "failing"}, // reliability degraded
		{nvmeLog(0x08, 3, 0), "failing"}, // read-only
	} {
		h, err := parseNVMeSMART(c.log)
		if err != nil {
			t.Fatal(err)
		}
		if got, reasons := h.verdict(); got != c.want {
			t.Errorf("warning %#x used %d media %d: %s %v, want %s", c.log[0], c.log[5], h.MediaErrors, got, reasons, c.want)
		}
	}
	h, _ := parseNVMeSMART(nvmeLog(0x05, 3, 0))
	if !slices.Equal(h.CriticalWarnings, []string{"available spare below threshold", "reliability degraded by media or internal errors"}) {
		t.Errorf("warnings %v", h.CriticalWarnings)
	}
	spare := nvmeLog(0, 3, 0)
	spare[3] = 5 // below the threshold of 10, without the bit
	h, _ = parseNVMeSMART(spare)
	if v, _ := h.verdict(); v != "failing" {
		t.Errorf("spare below threshold: %s", v)
	}
}

func TestATAVerdict(t *testing.T) {
	cases := []struct {
		passed bool
		attrs  [][5]uint64
		want   string
	}{
		{true, [][5]uint64{{5, 0x33, 100, 10, 0}}, "ok"},
		{true, [][5]uint64{{5, 0x33, 100, 10, 8}}, "warning"},  // reallocated sectors
		{true, [][5]uint64{{197, 0x22, 100, 0, 1}}, "warning"}, // pending
		{true, [][5]uint64{{5, 0x33, 9, 10, 900}}, "failing"},  // pre-failure at its threshold
		{true, [][5]uint64{{9, 0x32, 1, 2, 0}}, "warning"},     // old-age at its threshold
		{true, [][5]uint64{{5, 0x33, 100, 0xFE, 0}}, "ok"},     // "always passing"
		{false, [][5]uint64{{5, 0x33, 100, 10, 0}}, "failing"}, // the drive says so
	}
	for _, c := range cases {
		v, th := ataTables(c.attrs...)
		h, err := parseATASMART(c.passed, v, th)
		if err != nil {
			t.Fatal(err)
		}
		if got, reasons := h.verdict(); got != c.want {
			t.Errorf("%v %v: %s %v, want %s", c.passed, c.attrs, got, reasons, c.want)
		}
	}
	// Without thresholds (READ THRESHOLDS unsupported) nothing trips one.
	v, _ := ataTables([5]uint64{5, 0x33, 1, 10, 0})
	if h, _ := parseATASMART(true, v, nil); h.Attributes[0].Failing {
		t.Error("judged without a threshold")
	}
}

func TestSMARTStatusSense(t *testing.T) {
	fixed := make([]byte, 18)
	fixed[0], fixed[12], fixed[13] = 0x70, 0xF4, 0x2C
	for name, c := range map[string]struct {
		sense []byte
		ok    bool
		err   bool
	}{
		"descriptor ok":     {statusSense(0x4F, 0xC2), true, false},
		"descriptor failed": {statusSense(0xF4, 0x2C), false, false},
		"fixed failed":      {fixed, false, false},
		"odd registers":     {statusSense(0x00, 0x00), false, true},
		"no sense":          {nil, false, true},
	} {
		ok, err := smartStatusOK(c.sense)
		if ok != c.ok || (err != nil) != c.err {
			t.Errorf("%s: %v %v", name, ok, err)
		}
	}
}

func TestBtrfs(t *testing.T) {
	h, _, bfs := testHost(t)
	fss := h.btrfsDeviceStats()
	if len(fss) != 1 || fss[0].FSID != fsid || fss[0].MountPoint != "/" || fss[0].Label != "root" || len(fss[0].Devices) != 2 {
		t.Fatalf("filesystems %+v", fss)
	}
	d1, d2 := fss[0].Devices[0], fss[0].Devices[1]
	if d1.Devid != 1 || d1.Path != "/dev/nvme0n1p2" || d1.ReadIOErrs != 3 || d1.Source != "sysfs" || d1.Verdict != "warning" {
		t.Errorf("devid 1 %+v", d1)
	}
	if d2.Source != "ioctl" || d2.CorruptionErrs != 2 || d2.Verdict != "failing" {
		t.Errorf("devid 2 %+v", d2)
	}

	ss := h.btrfsScrubStatus()
	if len(ss) != 1 || ss[0].Running || ss[0].Last == nil {
		t.Fatalf("scrub %+v", ss)
	}
	l := ss[0].Last
	if l.Started != "2025-11-23T12:13:20Z" || l.DurationSeconds != 70 || !l.Finished || l.CsumErrors != 1 || l.Corrected != 1 ||
		l.BytesScrubbed != 1524 || ss[0].Verdict != "warning" {
		t.Errorf("last scrub %+v %s %v", l, ss[0].Verdict, ss[0].Reasons)
	}
	bfs.running = true
	if err := os.Remove(filepath.Join(h.scrubDir, "scrub.status."+fsid)); err != nil {
		t.Fatal(err)
	}
	if ss := h.btrfsScrubStatus(); !ss[0].Running || ss[0].Last != nil || ss[0].Verdict != "ok" {
		t.Errorf("running, none recorded: %+v", ss[0])
	}
	bfs.running = false
	if ss := h.btrfsScrubStatus(); ss[0].Verdict != "warning" || !strings.Contains(ss[0].Reasons[0], "no scrub recorded") {
		t.Errorf("never scrubbed: %+v", ss[0])
	}
}

func TestUnescapeMount(t *testing.T) {
	if got := unescapeMount(`/mnt/with\040space`); got != "/mnt/with space" {
		t.Errorf("%q", got)
	}
}

// The server over MCP: four read-only tools; device_health refuses a
// path and a device not listed.
func TestServer(t *testing.T) {
	h, _, _ := testHost(t)
	reqs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"storage_devices","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"device_health","arguments":{"device":"nvme0n1"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"device_health","arguments":{"device":"/dev/sda"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"btrfs_device_stats","arguments":{"reset":true}}}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"btrfs_scrub_status","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"btrfs_device_stats","arguments":{}}}`,
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	var errb bytes.Buffer
	done := make(chan int)
	go func() { done <- run(nil, inR, outW, &errb, h); _ = outW.Close() }()
	go func() {
		for _, r := range reqs {
			_, _ = io.WriteString(inW, r+"\n")
		}
	}()
	answers := map[float64]map[string]any{}
	sc := bufio.NewScanner(outR)
	sc.Buffer(nil, 1<<20)
	for len(answers) < len(reqs) && sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("%s: %v", sc.Text(), err)
		}
		answers[m["id"].(float64)] = m
	}
	_ = inW.Close()
	if rc := <-done; rc != 0 {
		t.Fatalf("rc %d: %s", rc, errb.String())
	}
	result := func(id float64) map[string]any { return answers[id]["result"].(map[string]any) }
	text := func(id float64) string {
		return result(id)["content"].([]any)[0].(map[string]any)["text"].(string)
	}
	var names []string
	for _, x := range result(2)["tools"].([]any) {
		tl := x.(map[string]any)
		names = append(names, tl["name"].(string))
		if ann := tl["annotations"].(map[string]any); ann["readOnlyHint"] != true || ann["destructiveHint"] != false {
			t.Errorf("%s annotations %v", tl["name"], ann)
		}
		if n := tl["name"].(string); strings.HasPrefix(n, "list_") || strings.HasPrefix(n, "read_") || strings.HasPrefix(n, "get_") {
			t.Errorf("%s: a prefix the viewer role allows", n)
		}
	}
	if !slices.Equal(names, []string{"storage_devices", "device_health", "btrfs_device_stats", "btrfs_scrub_status"}) {
		t.Errorf("tools %v", names)
	}
	if !strings.Contains(text(3), "nvme0n1: nvme Fake NVMe SSD 1TB") || result(3)["structuredContent"] == nil {
		t.Errorf("storage_devices: %v", result(3))
	}
	if !strings.HasPrefix(text(4), "nvme0n1 (nvme Fake NVMe SSD 1TB): ok") {
		t.Errorf("device_health: %v", result(4))
	}
	if result(5)["isError"] != true || !strings.Contains(text(5), "not an NVMe namespace") {
		t.Errorf("a path: %v", result(5))
	}
	if result(6)["isError"] != true || !strings.Contains(text(6), "unknown argument \"reset\"") {
		t.Errorf("an argument: %v", result(6))
	}
	if !strings.Contains(text(7), "/: warning, last scrub 2025-11-23T12:13:20Z") {
		t.Errorf("btrfs_scrub_status: %q", text(7))
	}
	if !strings.Contains(text(8), "/ devid 2 /dev/sda1: failing: 2 corruption errors") {
		t.Errorf("btrfs_device_stats: %q", text(8))
	}
}
