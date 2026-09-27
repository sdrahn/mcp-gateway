package supervisor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ForeignProc is a process of another workload holding an MCS category
// pair: a container (podman) or virtual machine (libvirt).
type ForeignProc struct {
	PID     int
	Context string
}

// LibvirtDaemon is a running libvirt daemon and the category range it
// picks its sVirt pairs from (its own process range).
type LibvirtDaemon struct {
	PID     int
	Context string
	Lo, Hi  int
}

// MCSScan is what ScanMCS found.
type MCSScan struct {
	// Pairs held by processes other than the gateway's backends.
	Pairs map[[2]int]ForeignProc
	// Libvirt daemons, which pick pairs from their own category range.
	Libvirt []LibvirtDaemon
}

// libvirtTypes are the domains of libvirt daemons (monolithic and modular).
var libvirtTypes = map[string]bool{"virtd_t": true, "virtqemud_t": true, "virtlxcd_t": true}

// ScanMCS reads the SELinux contexts of the processes below procRoot
// ("/proc"). Processes it may not read are skipped: the gateway's policy
// lets it read container and virtual machine domains only.
func ScanMCS(procRoot string) MCSScan {
	scan := MCSScan{Pairs: map[[2]int]ForeignProc{}}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return scan
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "attr", "current"))
		if err != nil {
			continue
		}
		ctx := strings.TrimRight(string(b), "\x00\n")
		parts := strings.SplitN(ctx, ":", 4)
		if len(parts) != 4 {
			continue
		}
		typ, level := parts[2], parts[3]
		if libvirtTypes[typ] {
			lo, hi := categoryRange(level)
			scan.Libvirt = append(scan.Libvirt, LibvirtDaemon{PID: pid, Context: ctx, Lo: lo, Hi: hi})
			continue
		}
		if strings.HasPrefix(typ, "mcpsrv_") {
			continue // ours
		}
		if pair, ok := parsePair(level); ok {
			scan.Pairs[pair] = ForeignProc{PID: pid, Context: ctx}
		}
	}
	return scan
}

// parsePair extracts the category pair of a level like "s0:c12,c40" (or
// "s0-s0:c12,c40").
func parsePair(level string) ([2]int, bool) {
	_, cats, ok := strings.Cut(level, ":")
	if !ok {
		return [2]int{}, false
	}
	var a, b int
	if _, err := fmt.Sscanf(cats, "c%d,c%d", &a, &b); err != nil || fmt.Sprintf("c%d,c%d", a, b) != cats || a == b {
		return [2]int{}, false
	}
	if a > b {
		a, b = b, a
	}
	return [2]int{a, b}, true
}

// categoryRange returns the category range of a process level such as
// "s0-s0:c0.c1023", as libvirt reads it: all categories when none are
// given.
func categoryRange(level string) (lo, hi int) {
	_, cats, ok := strings.Cut(level, ":")
	if !ok {
		return 0, 1023
	}
	if _, err := fmt.Sscanf(cats, "c%d.c%d", &lo, &hi); err == nil {
		return lo, hi
	}
	if _, err := fmt.Sscanf(cats, "c%d", &lo); err == nil {
		return lo, lo
	}
	return 0, 1023
}

// Overlapping returns the libvirt daemons whose category range overlaps
// lo..hi, so their virtual machines may get pairs from the gateway's
// range.
func (s MCSScan) Overlapping(lo, hi int) []LibvirtDaemon {
	var out []LibvirtDaemon
	for _, d := range s.Libvirt {
		if d.Lo <= hi && lo <= d.Hi {
			out = append(out, d)
		}
	}
	return out
}

// WatchMCS calls check with a fresh scan of procRoot every interval until
// ctx ends.
func WatchMCS(ctx context.Context, procRoot string, interval time.Duration, check func(MCSScan)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check(ScanMCS(procRoot))
		}
	}
}
