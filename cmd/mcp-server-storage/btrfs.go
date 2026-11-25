package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// btrfs: the mounted file systems (mountinfo), each once, with their
// devices and error counters (sysfs devinfo/<devid>/error_stats, kernel
// 5.14 and later; else BTRFS_IOC_GET_DEV_STATS without reset) and the
// last scrub (btrfs-progs' /var/lib/btrfs/scrub.status.<fsid>), and
// whether one runs (BTRFS_IOC_SCRUB_PROGRESS). The device and scrub
// ioctls need CAP_SYS_ADMIN.

const (
	btrfsIocFSInfo        = 0x8400941F // _IOR(0x94, 31, struct btrfs_ioctl_fs_info_args)
	btrfsIocDevInfo       = 0xD000941E // _IOWR(0x94, 30, struct btrfs_ioctl_dev_info_args)
	btrfsIocGetDevStats   = 0xC4089434 // _IOWR(0x94, 52, struct btrfs_ioctl_get_dev_stats)
	btrfsIocScrubProgress = 0xC400941D // _IOWR(0x94, 29, struct btrfs_ioctl_scrub_args)
)

// btrfsMount is a mounted btrfs: its fsid and one mount point to ask.
type btrfsMount struct {
	FSID       string
	MountPoint string
	Devids     []uint64
}

// btrfsIO is what the kernel answers about a btrfs; fake in tests.
type btrfsIO interface {
	// fsid is the file system's UUID, through the mount point.
	fsid(mountPoint string) (string, error)
	// devPath is the device of devid.
	devPath(mountPoint string, devid uint64) (string, error)
	// devStats are the counters (write, read, flush, corruption,
	// generation), not reset.
	devStats(mountPoint string, devid uint64) ([5]uint64, error)
	// scrubRunning: a scrub runs on devid.
	scrubRunning(mountPoint string, devid uint64) (bool, error)
}

// btrfsMounts are the mounted btrfs file systems, each once (by fsid),
// asked through its shortest mount point.
func (h *host) btrfsMounts() []btrfsMount {
	f, err := os.Open(h.mountinfo)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var points []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// id parent major:minor root mountpoint options... - fstype source superoptions
		pre, post, ok := strings.Cut(sc.Text(), " - ")
		fields, after := strings.Fields(pre), strings.Fields(post)
		if !ok || len(fields) < 5 || len(after) < 1 || after[0] != "btrfs" {
			continue
		}
		points = append(points, unescapeMount(fields[4]))
	}
	slices.SortFunc(points, func(a, b string) int { return len(a) - len(b) })
	byFSID := map[string]*btrfsMount{}
	var out []btrfsMount
	for _, p := range points {
		fsid, err := h.btrfs.fsid(p)
		if err != nil || byFSID[fsid] != nil {
			continue
		}
		m := btrfsMount{FSID: fsid, MountPoint: p}
		entries, _ := os.ReadDir(filepath.Join(h.sys, "fs", "btrfs", fsid, "devinfo"))
		for _, e := range entries {
			if id, err := strconv.ParseUint(e.Name(), 10, 64); err == nil {
				m.Devids = append(m.Devids, id)
			}
		}
		slices.Sort(m.Devids)
		out = append(out, m)
		byFSID[fsid] = &out[len(out)-1]
	}
	slices.SortFunc(out, func(a, b btrfsMount) int { return strings.Compare(a.MountPoint, b.MountPoint) })
	return out
}

// unescapeMount undoes mountinfo's octal escapes (\040 for a space).
func unescapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// BtrfsFS is a mounted btrfs as btrfs_device_stats reports it.
type BtrfsFS struct {
	FSID       string        `json:"fsid"`
	Label      string        `json:"label,omitempty"`
	MountPoint string        `json:"mount_point"`
	Devices    []BtrfsDevice `json:"devices"`
}

// BtrfsDevice is a device's error counters since they were last reset.
type BtrfsDevice struct {
	Devid          uint64   `json:"devid"`
	Path           string   `json:"path,omitempty"`
	WriteIOErrs    uint64   `json:"write_io_errs"`
	ReadIOErrs     uint64   `json:"read_io_errs"`
	FlushIOErrs    uint64   `json:"flush_io_errs"`
	CorruptionErrs uint64   `json:"corruption_errs"`
	GenerationErrs uint64   `json:"generation_errs"`
	Source         string   `json:"source"` // sysfs or ioctl
	Verdict        string   `json:"verdict"`
	Reasons        []string `json:"reasons"`
	Error          string   `json:"error,omitempty"`
}

// errorStatNames are sysfs error_stats' names, in the ioctl's order.
var errorStatNames = []string{"write_errs", "read_errs", "flush_errs", "corruption_errs", "generation_errs"}

func (h *host) btrfsDeviceStats() []BtrfsFS {
	out := []BtrfsFS{}
	for _, m := range h.btrfsMounts() {
		fs := BtrfsFS{FSID: m.FSID, MountPoint: m.MountPoint, Devices: []BtrfsDevice{},
			Label: readString(filepath.Join(h.sys, "fs", "btrfs", m.FSID, "label"))}
		for _, id := range m.Devids {
			d := BtrfsDevice{Devid: id}
			d.Path, _ = h.btrfs.devPath(m.MountPoint, id)
			v, err := readErrorStats(filepath.Join(h.sys, "fs", "btrfs", m.FSID, "devinfo", strconv.FormatUint(id, 10), "error_stats"))
			d.Source = "sysfs"
			if err != nil {
				d.Source = "ioctl"
				v, err = h.btrfs.devStats(m.MountPoint, id)
			}
			if err != nil {
				d.Error, d.Verdict, d.Reasons = err.Error(), "unknown", []string{}
				fs.Devices = append(fs.Devices, d)
				continue
			}
			d.WriteIOErrs, d.ReadIOErrs, d.FlushIOErrs, d.CorruptionErrs, d.GenerationErrs = v[0], v[1], v[2], v[3], v[4]
			d.Verdict, d.Reasons = d.verdict()
			fs.Devices = append(fs.Devices, d)
		}
		out = append(out, fs)
	}
	return out
}

// verdict: failing on corruption or generation errors (data or metadata
// found wrong), warning on I/O errors.
func (d BtrfsDevice) verdict() (string, []string) {
	var failing, warning []string
	for _, c := range []struct {
		n    uint64
		name string
		fail bool
	}{{d.WriteIOErrs, "write I/O errors", false}, {d.ReadIOErrs, "read I/O errors", false}, {d.FlushIOErrs, "flush I/O errors", false},
		{d.CorruptionErrs, "corruption errors", true}, {d.GenerationErrs, "generation errors", true}} {
		if c.n == 0 {
			continue
		}
		msg := fmt.Sprintf("%d %s", c.n, c.name)
		if c.fail {
			failing = append(failing, msg)
		} else {
			warning = append(warning, msg)
		}
	}
	return judge(failing, warning)
}

// readErrorStats reads sysfs error_stats ("write_errs 0" per line).
func readErrorStats(path string) ([5]uint64, error) {
	var v [5]uint64
	b, err := os.ReadFile(path)
	if err != nil {
		return v, err
	}
	seen := 0
	for _, line := range strings.Split(string(b), "\n") {
		name, val, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		if i := slices.Index(errorStatNames, name); i >= 0 {
			n, err := strconv.ParseUint(strings.TrimSpace(val), 10, 64)
			if err != nil {
				return v, fmt.Errorf("%s: %s: %w", path, name, err)
			}
			v[i] = n
			seen++
		}
	}
	if seen != len(errorStatNames) {
		return v, fmt.Errorf("%s: %d of %d counters", path, seen, len(errorStatNames))
	}
	return v, nil
}

// BtrfsScrub is a btrfs's scrub as btrfs_scrub_status reports it.
type BtrfsScrub struct {
	FSID       string     `json:"fsid"`
	Label      string     `json:"label,omitempty"`
	MountPoint string     `json:"mount_point"`
	Running    bool       `json:"running"`
	Last       *LastScrub `json:"last_scrub"`
	Verdict    string     `json:"verdict"`
	Reasons    []string   `json:"reasons"`
}

// LastScrub is the last scrub btrfs-progs recorded, summed over the
// devices.
type LastScrub struct {
	Started         string `json:"started,omitempty"`
	DurationSeconds uint64 `json:"duration_seconds"`
	Finished        bool   `json:"finished"`
	Canceled        bool   `json:"canceled"`
	BytesScrubbed   uint64 `json:"bytes_scrubbed"`
	ReadErrors      uint64 `json:"read_errors"`
	CsumErrors      uint64 `json:"csum_errors"`
	VerifyErrors    uint64 `json:"verify_errors"`
	SuperErrors     uint64 `json:"super_errors"`
	Uncorrectable   uint64 `json:"uncorrectable_errors"`
	Corrected       uint64 `json:"corrected_errors"`
}

func (h *host) btrfsScrubStatus() []BtrfsScrub {
	out := []BtrfsScrub{}
	for _, m := range h.btrfsMounts() {
		s := BtrfsScrub{FSID: m.FSID, MountPoint: m.MountPoint, Label: readString(filepath.Join(h.sys, "fs", "btrfs", m.FSID, "label"))}
		for _, id := range m.Devids {
			if r, err := h.btrfs.scrubRunning(m.MountPoint, id); err == nil && r {
				s.Running = true
			}
		}
		s.Last, _ = readScrubStatus(filepath.Join(h.scrubDir, "scrub.status."+m.FSID))
		s.Verdict, s.Reasons = s.verdict()
		out = append(out, s)
	}
	return out
}

// verdict: failing on uncorrectable errors in the last scrub, warning on
// any other error it found, or when none is recorded.
func (s BtrfsScrub) verdict() (string, []string) {
	if s.Last == nil {
		if s.Running {
			return "ok", []string{"a scrub runs; none recorded before"}
		}
		return "warning", []string{"no scrub recorded (btrfs scrub start, or the btrfsmaintenance timer)"}
	}
	var failing, warning []string
	if s.Last.Uncorrectable > 0 {
		failing = append(failing, fmt.Sprintf("%d uncorrectable errors", s.Last.Uncorrectable))
	}
	if n := s.Last.ReadErrors + s.Last.CsumErrors + s.Last.VerifyErrors + s.Last.SuperErrors; n > 0 {
		warning = append(warning, fmt.Sprintf("%d errors found (%d corrected)", n, s.Last.Corrected))
	}
	if s.Last.Canceled {
		warning = append(warning, "the last scrub was canceled")
	}
	return judge(failing, warning)
}

// readScrubStatus reads btrfs-progs' scrub status file: "scrub status:1",
// then a line per device "<fsid>:<devid>|key:value|...". Nil without
// one.
func readScrubStatus(path string) (*LastScrub, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var last *LastScrub
	var start uint64
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.Split(strings.TrimSpace(line), "|")
		if len(parts) < 2 {
			continue
		}
		kv := map[string]uint64{}
		for _, p := range parts[1:] {
			k, v, ok := strings.Cut(p, ":")
			if !ok {
				continue
			}
			if n, err := strconv.ParseUint(v, 10, 64); err == nil {
				kv[k] = n
			}
		}
		if last == nil {
			last = &LastScrub{Finished: true}
		}
		last.BytesScrubbed += kv["data_bytes_scrubbed"] + kv["tree_bytes_scrubbed"]
		last.ReadErrors += kv["read_errors"]
		last.CsumErrors += kv["csum_errors"]
		last.VerifyErrors += kv["verify_errors"]
		last.SuperErrors += kv["super_errors"]
		last.Uncorrectable += kv["uncorrectable_errors"]
		last.Corrected += kv["corrected_errors"]
		last.DurationSeconds = max(last.DurationSeconds, kv["duration"])
		last.Finished = last.Finished && kv["finished"] == 1
		last.Canceled = last.Canceled || kv["canceled"] == 1
		if t := kv["t_start"]; t > 0 && (start == 0 || t < start) {
			start = t
		}
	}
	if last == nil {
		return nil, errors.New(path + ": no devices")
	}
	if start > 0 {
		last.Started = time.Unix(int64(start), 0).UTC().Format(time.RFC3339)
	}
	return last, nil
}

// kernelBtrfs asks the kernel, through a mount point (opened read-only,
// as a directory).
type kernelBtrfs struct{}

func withDir(mountPoint string, f func(fd int) error) error {
	fd, err := unix.Open(mountPoint, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	return f(fd)
}

func ioctl(fd int, req uintptr, arg unsafe.Pointer) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}

func formatUUID(b []byte) string {
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func (kernelBtrfs) fsid(mountPoint string) (string, error) {
	var args [1024]byte // struct btrfs_ioctl_fs_info_args; fsid at 16
	err := withDir(mountPoint, func(fd int) error { return ioctl(fd, btrfsIocFSInfo, unsafe.Pointer(&args)) })
	if err != nil {
		return "", fmt.Errorf("BTRFS_IOC_FS_INFO %s: %w", mountPoint, err)
	}
	return formatUUID(args[16:32]), nil
}

func (kernelBtrfs) devPath(mountPoint string, devid uint64) (string, error) {
	var args [4096]byte // struct btrfs_ioctl_dev_info_args; devid at 0, path at 3072
	*(*uint64)(unsafe.Pointer(&args[0])) = devid
	err := withDir(mountPoint, func(fd int) error { return ioctl(fd, btrfsIocDevInfo, unsafe.Pointer(&args)) })
	if err != nil {
		return "", fmt.Errorf("BTRFS_IOC_DEV_INFO %s %d: %w", mountPoint, devid, err)
	}
	p := args[3072:]
	if i := slices.Index(p, 0); i >= 0 {
		p = p[:i]
	}
	return string(p), nil
}

func (kernelBtrfs) devStats(mountPoint string, devid uint64) ([5]uint64, error) {
	var args [1032 / 8]uint64               // struct btrfs_ioctl_get_dev_stats: devid, nr_items, flags, values[5], ...
	args[0], args[1], args[2] = devid, 5, 0 // flags 0: never BTRFS_DEV_STATS_RESET
	err := withDir(mountPoint, func(fd int) error { return ioctl(fd, btrfsIocGetDevStats, unsafe.Pointer(&args)) })
	if err != nil {
		return [5]uint64{}, fmt.Errorf("BTRFS_IOC_GET_DEV_STATS %s %d: %w", mountPoint, devid, err)
	}
	return [5]uint64{args[3], args[4], args[5], args[6], args[7]}, nil
}

func (kernelBtrfs) scrubRunning(mountPoint string, devid uint64) (bool, error) {
	var args [1024 / 8]uint64 // struct btrfs_ioctl_scrub_args; devid at 0
	args[0] = devid
	err := withDir(mountPoint, func(fd int) error { return ioctl(fd, btrfsIocScrubProgress, unsafe.Pointer(&args)) })
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.ENOTCONN):
		return false, nil
	}
	return false, fmt.Errorf("BTRFS_IOC_SCRUB_PROGRESS %s %d: %w", mountPoint, devid, err)
}
