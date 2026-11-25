package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Device is a disk as storage_devices lists it.
type Device struct {
	Name      string `json:"name"`
	Model     string `json:"model,omitempty"`
	Serial    string `json:"serial,omitempty"`
	Firmware  string `json:"firmware,omitempty"`
	SizeBytes uint64 `json:"size_bytes"`
	// Transport is nvme, sata, usb, scsi, virtio, dm, md, loop or other.
	Transport  string `json:"transport"`
	Rotational bool   `json:"rotational"`
	// Health: device_health can report on it; else HealthNote says why
	// not.
	Health     bool   `json:"health_available"`
	HealthNote string `json:"health_note,omitempty"`
}

// healthName is a device device_health takes: an NVMe namespace or a
// SCSI disk (SATA behind libata).
var healthName = regexp.MustCompile(`^(nvme[0-9]+n[0-9]+|sd[a-z]+)$`)

// devices lists the whole disks below sys/class/block (no partitions),
// by name.
func (h *host) devices() []Device {
	dir := filepath.Join(h.sys, "class", "block")
	entries, _ := os.ReadDir(dir)
	out := []Device{}
	for _, e := range entries {
		name := e.Name()
		base := filepath.Join(dir, name)
		if exists(filepath.Join(base, "partition")) || strings.HasPrefix(name, "ram") || strings.HasPrefix(name, "zram") {
			continue
		}
		d := Device{Name: name, SizeBytes: readUint(filepath.Join(base, "size")) * 512,
			Rotational: readString(filepath.Join(base, "queue", "rotational")) == "1"}
		dev := filepath.Join(base, "device")
		target, _ := filepath.EvalSymlinks(dev)
		switch {
		case strings.HasPrefix(name, "nvme"):
			// A namespace's device is its controller.
			d.Transport = "nvme"
			d.Model, d.Serial, d.Firmware = readString(filepath.Join(dev, "model")), readString(filepath.Join(dev, "serial")),
				readString(filepath.Join(dev, "firmware_rev"))
		case strings.HasPrefix(name, "sd"):
			d.Model = strings.TrimSpace(readString(filepath.Join(dev, "vendor")) + " " + readString(filepath.Join(dev, "model")))
			d.Serial = vpdSerial(filepath.Join(dev, "vpd_pg80"))
			d.Firmware = readString(filepath.Join(dev, "rev"))
			switch {
			case strings.Contains(target, "/usb"):
				d.Transport = "usb"
			case strings.Contains(target, "/ata"):
				d.Transport = "sata"
			default:
				d.Transport = "scsi"
			}
		case strings.HasPrefix(name, "vd"):
			d.Transport = "virtio"
			d.Serial = readString(filepath.Join(base, "serial"))
		case strings.HasPrefix(name, "dm-"):
			d.Transport = "dm"
		case strings.HasPrefix(name, "md"):
			d.Transport = "md"
		case strings.HasPrefix(name, "loop"):
			d.Transport = "loop"
		default:
			d.Transport = "other"
		}
		switch {
		case !healthName.MatchString(name):
			d.HealthNote = "no SMART or NVMe health log: " + d.Transport + " device"
		case d.Transport == "nvme" || d.Transport == "sata":
			d.Health = true
		default:
			d.HealthNote = "SMART only for SATA disks behind libata, not over " + d.Transport
		}
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b Device) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// vpdSerial is the unit serial number of a SCSI disk's VPD page 0x80.
func vpdSerial(path string) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) < 4 {
		return ""
	}
	n := int(b[3])
	if 4+n > len(b) {
		n = len(b) - 4
	}
	return strings.TrimSpace(string(b[4 : 4+n]))
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readString(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readUint(path string) uint64 {
	n, _ := strconv.ParseUint(readString(path), 10, 64)
	return n
}
