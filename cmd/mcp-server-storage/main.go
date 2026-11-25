// Command mcp-server-storage is an MCP server, run by mcp-gateway as the
// server "storage" (package mcp-gateway-storage-server), that reports
// storage health, read only: the disks, the SMART or NVMe health of
// one, the btrfs device error counters and the btrfs scrub status. Each
// call reads the devices and the kernel then and there (no smartd or
// other daemon, no state of one). It never resets a counter, starts a
// scrub or a self-test, or writes to a device. Its definition names the
// device classes it reads and the capabilities that takes: CAP_SYS_ADMIN
// (NVMe admin passthrough, btrfs ioctls), CAP_SYS_RAWIO (ATA
// passthrough) and CAP_DAC_READ_SEARCH (opening the disks, root:disk
// 0660, for reading).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/sdrahn/mcp-gateway/internal/mcpserver"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

const serverName = "mcp-server-storage"

// host is where the server reads: the paths and the device ioctls, set
// apart for the tests.
type host struct {
	sys       string // /sys
	dev       string // /dev
	mountinfo string // /proc/self/mountinfo
	scrubDir  string // /var/lib/btrfs
	disk      diskIO
	btrfs     btrfsIO
}

// diskIO reads a disk's health log through its device node; fake in
// tests.
type diskIO interface {
	nvmeSMART(path string) ([]byte, error)
	ataSMART(path string) (status []byte, values, thresholds []byte, err error)
}

func newHost() *host {
	return &host{sys: "/sys", dev: "/dev", mountinfo: "/proc/self/mountinfo", scrubDir: "/var/lib/btrfs",
		disk: kernelDisk{}, btrfs: kernelBtrfs{}}
}

// kernelDisk opens the device for reading only, never writing.
type kernelDisk struct{}

func withDevice(path string, f func(fd int) error) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	return f(fd)
}

func (kernelDisk) nvmeSMART(path string) (b []byte, err error) {
	err = withDevice(path, func(fd int) error { b, err = nvmeSMARTLog(fd); return err })
	return b, err
}

func (kernelDisk) ataSMART(path string) (status, values, thresholds []byte, err error) {
	err = withDevice(path, func(fd int) error { status, values, thresholds, err = ataSMARTRead(fd); return err })
	return status, values, thresholds, err
}

// Health is device_health's answer.
type Health struct {
	Device     string      `json:"device"`
	Transport  string      `json:"transport"`
	Model      string      `json:"model,omitempty"`
	Serial     string      `json:"serial,omitempty"`
	Verdict    string      `json:"verdict"`
	Reasons    []string    `json:"reasons"`
	Thresholds any         `json:"thresholds"`
	NVMe       *NVMeHealth `json:"nvme,omitempty"`
	ATA        *ATAHealth  `json:"ata,omitempty"`
}

// deviceHealth reads the health of name, which must be one devices lists
// with health available: never a path.
func (h *host) deviceHealth(name string) (Health, error) {
	if !healthName.MatchString(name) {
		return Health{}, fmt.Errorf("device %q: not an NVMe namespace (nvme0n1) or SATA disk (sda) name; storage_devices lists them", name)
	}
	var d *Device
	for _, x := range h.devices() {
		if x.Name == name {
			d = &x
			break
		}
	}
	switch {
	case d == nil:
		return Health{}, fmt.Errorf("device %s: not on this host (storage_devices lists the disks)", name)
	case !d.Health:
		return Health{}, fmt.Errorf("device %s: %s", name, d.HealthNote)
	}
	out := Health{Device: name, Transport: d.Transport, Model: d.Model, Serial: d.Serial}
	path := filepath.Join(h.dev, name)
	switch d.Transport {
	case "nvme":
		raw, err := h.disk.nvmeSMART(path)
		if err != nil {
			return Health{}, fmt.Errorf("device %s: %w", name, err)
		}
		n, err := parseNVMeSMART(raw)
		if err != nil {
			return Health{}, err
		}
		out.NVMe = &n
		out.Verdict, out.Reasons = n.verdict()
		out.Thresholds = map[string]any{
			"failing": "critical warning: spare below threshold, reliability degraded or read-only media; or available spare below its threshold",
			"warning": fmt.Sprintf("other critical warnings, media and data integrity errors above 0, percentage used from %d", nvmeUsedWarning),
		}
	default:
		status, values, thresholds, err := h.disk.ataSMART(path)
		if err != nil {
			return Health{}, fmt.Errorf("device %s: %w", name, err)
		}
		passed, err := smartStatusOK(status)
		if err != nil {
			return Health{}, fmt.Errorf("device %s: %w", name, err)
		}
		a, err := parseATASMART(passed, values, thresholds)
		if err != nil {
			return Health{}, err
		}
		out.ATA = &a
		out.Verdict, out.Reasons = a.verdict()
		out.Thresholds = map[string]any{
			"failing": "SMART RETURN STATUS reports a threshold exceeded, or a pre-failure attribute at or below its threshold",
			"warning": "another attribute at or below its threshold, or a raw count above 0 of attributes 5, 187, 197 or 198",
		}
	}
	return out, nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, newHost()))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, h *host) int {
	fs := flag.NewFlagSet(serverName, flag.ContinueOnError)
	fs.SetOutput(stderr)
	once := fs.String("once", "", "print what one tool returns (JSON) and exit: devices, health=NAME, btrfs-stats, btrfs-scrub")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "usage: %s [options]\n\nAn MCP server, on stdin/stdout, that reports storage health, read only.\n\n", serverName)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *showVersion {
		_, _ = fmt.Fprintln(stdout, serverName, version.Version)
		return 0
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	if *once != "" {
		var v any
		switch name, arg, _ := strings.Cut(*once, "="); name {
		case "devices":
			v = h.devices()
		case "health":
			hl, err := h.deviceHealth(arg)
			if err != nil {
				_, _ = fmt.Fprintln(stderr, serverName+":", err)
				return 1
			}
			v = hl
		case "btrfs-stats":
			v = h.btrfsDeviceStats()
		case "btrfs-scrub":
			v = h.btrfsScrubStatus()
		default:
			fs.Usage()
			return 2
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if enc.Encode(v) != nil {
			return 1
		}
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "%s: ready\n", serverName)
	s := &server{h: h}
	if err := mcpserver.New(s.handle, stdout).Serve(stdin, 1<<20); err != nil {
		_, _ = fmt.Fprintln(stderr, serverName+":", err)
		return 1
	}
	return 0
}

type server struct {
	h *host
}

const instructions = "Storage health on this host, read only: storage_devices lists the disks; device_health reads one NVMe or SATA disk's " +
	"health log (NVMe SMART / Health Information, or SATA SMART) with a verdict ok, warning or failing; btrfs_device_stats gives each " +
	"mounted btrfs device's error counters; btrfs_scrub_status the last scrub and whether one runs. Every call reads the devices now. " +
	"Nothing here starts a scrub or self-test, resets a counter or writes to a device."

type tool struct {
	name, title, description string
	input                    map[string]any
	call                     func(args map[string]any) (any, string, error)
}

var noArgs = map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}

func (s *server) tools() []tool {
	return []tool{
		{"storage_devices", "Storage devices",
			"The disks of this host (from sysfs): name, model, serial, firmware, size, transport (nvme, sata, usb, scsi, virtio, dm, md, loop) " +
				"and whether device_health can report on it. Reads only; takes no arguments.",
			noArgs, func(map[string]any) (any, string, error) {
				d := s.h.devices()
				var b strings.Builder
				for _, x := range d {
					fmt.Fprintf(&b, "%s: %s %s, %d GB, %s", x.Name, x.Transport, orDash(x.Model), x.SizeBytes/1e9, map[bool]string{true: "health available", false: x.HealthNote}[x.Health])
					b.WriteString("\n")
				}
				if len(d) == 0 {
					b.WriteString("no disks found\n")
				}
				return map[string]any{"devices": d}, b.String(), nil
			}},
		{"device_health", "Device health",
			"The health of one disk that storage_devices lists with health available: for NVMe the SMART / Health Information log " +
				"(critical warning, temperature, spare, percentage used, media errors, error log entries, power-on hours, unsafe shutdowns), " +
				"for SATA the drive's SMART status and attribute table; with a verdict ok, warning or failing and the thresholds it used. " +
				"Reads only: no self-test is started.",
			map[string]any{"type": "object", "additionalProperties": false, "required": []string{"device"}, "properties": map[string]any{
				"device": map[string]any{"type": "string", "pattern": healthName.String(), "description": "a disk's name as storage_devices lists it, e.g. nvme0n1 or sda; not a path"},
			}},
			func(args map[string]any) (any, string, error) {
				name, _ := args["device"].(string)
				hl, err := s.h.deviceHealth(name)
				if err != nil {
					return nil, "", err
				}
				text := fmt.Sprintf("%s (%s %s): %s", hl.Device, hl.Transport, orDash(hl.Model), hl.Verdict)
				if len(hl.Reasons) > 0 {
					text += ": " + strings.Join(hl.Reasons, "; ")
				}
				return hl, text + "\n", nil
			}},
		{"btrfs_device_stats", "Btrfs device errors",
			"For each mounted btrfs, each device's error counters since they were last reset: write, read and flush I/O errors, " +
				"corruption and generation errors, with a verdict. Reads only: the counters are never reset. Takes no arguments.",
			noArgs, func(map[string]any) (any, string, error) {
				fss := s.h.btrfsDeviceStats()
				var b strings.Builder
				for _, f := range fss {
					for _, d := range f.Devices {
						fmt.Fprintf(&b, "%s devid %d %s: %s", f.MountPoint, d.Devid, orDash(d.Path), d.Verdict)
						if len(d.Reasons) > 0 {
							b.WriteString(": " + strings.Join(d.Reasons, "; "))
						}
						if d.Error != "" {
							b.WriteString(": " + d.Error)
						}
						b.WriteString("\n")
					}
				}
				if len(fss) == 0 {
					b.WriteString("no btrfs mounted\n")
				}
				return map[string]any{"filesystems": fss}, b.String(), nil
			}},
		{"btrfs_scrub_status", "Btrfs scrub status",
			"For each mounted btrfs, whether a scrub runs and the last one recorded (start, duration, finished or canceled, errors found, " +
				"corrected and uncorrectable), with a verdict. Reads only: never starts a scrub. Takes no arguments.",
			noArgs, func(map[string]any) (any, string, error) {
				ss := s.h.btrfsScrubStatus()
				var b strings.Builder
				for _, x := range ss {
					fmt.Fprintf(&b, "%s: %s", x.MountPoint, x.Verdict)
					if x.Running {
						b.WriteString(", a scrub runs")
					}
					if x.Last != nil {
						fmt.Fprintf(&b, ", last scrub %s", orDash(x.Last.Started))
					}
					if len(x.Reasons) > 0 {
						b.WriteString(": " + strings.Join(x.Reasons, "; "))
					}
					b.WriteString("\n")
				}
				if len(ss) == 0 {
					b.WriteString("no btrfs mounted\n")
				}
				return map[string]any{"filesystems": ss}, b.String(), nil
			}},
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (s *server) handle(ctx context.Context, method string, params json.RawMessage) (any, error) {
	switch method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(params, &p)
		return map[string]any{
			"protocolVersion": mcpserver.Negotiate(p.ProtocolVersion),
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": serverName, "title": "Storage health", "version": version.Version},
			"instructions":    instructions,
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		var list []map[string]any
		for _, t := range s.tools() {
			list = append(list, map[string]any{"name": t.name, "title": t.title, "description": t.description, "inputSchema": t.input,
				"annotations": map[string]any{"title": t.title, "readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false}})
		}
		return map[string]any{"tools": list}, nil
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &mcpserver.Error{Code: mcpserver.CodeInvalidParams, Message: "invalid params"}
		}
		for _, t := range s.tools() {
			if t.name != p.Name {
				continue
			}
			for k := range p.Arguments {
				if _, ok := t.input["properties"].(map[string]any)[k]; !ok {
					return toolError("%s: unknown argument %s", t.name, strconv.Quote(k)), nil
				}
			}
			v, text, err := t.call(p.Arguments)
			if err != nil {
				return toolError("%v", err), nil
			}
			return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "structuredContent": v}, nil
		}
		return nil, &mcpserver.Error{Code: mcpserver.CodeInvalidParams, Message: "unknown tool " + strconv.Quote(p.Name)}
	}
	return nil, &mcpserver.Error{Code: mcpserver.CodeMethodNotFound, Message: "method not found"}
}

func toolError(format string, a ...any) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": fmt.Sprintf(format, a...)}}, "isError": true}
}
