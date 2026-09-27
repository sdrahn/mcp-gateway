package supervisor

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// fakeProc writes contexts as /proc/<pid>/attr/current files.
func fakeProc(t *testing.T, contexts map[int]string) string {
	t.Helper()
	root := t.TempDir()
	for pid, ctx := range contexts {
		dir := filepath.Join(root, strconv.Itoa(pid), "attr")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "current"), []byte(ctx+"\x00"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Not a process.
	if err := os.MkdirAll(filepath.Join(root, "sys"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestScanMCS(t *testing.T) {
	root := fakeProc(t, map[int]string{
		10: "system_u:system_r:container_t:s0:c900,c812",
		11: "system_u:system_r:svirt_t:s0:c5,c1000",
		12: "system_u:system_r:mcpsrv_fs_t:s0:c800,c801", // ours
		13: "system_u:system_r:virtqemud_t:s0-s0:c0.c767",
		14: "system_u:system_r:virtd_t:s0-s0:c0.c1023",
		15: "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023",
		16: "system_u:system_r:container_t:s0:c7,c7",
		17: "garbage",
	})
	scan := ScanMCS(root)
	if len(scan.Pairs) != 2 || scan.Pairs[[2]int{812, 900}].PID != 10 || scan.Pairs[[2]int{5, 1000}].PID != 11 {
		t.Fatalf("pairs %+v", scan.Pairs)
	}
	if len(scan.Libvirt) != 2 {
		t.Fatalf("libvirt %+v", scan.Libvirt)
	}
	over := scan.Overlapping(768, 1023)
	if len(over) != 1 || over[0].PID != 14 {
		t.Fatalf("overlapping %+v", over)
	}
	if got := ScanMCS(filepath.Join(root, "missing")); len(got.Pairs) != 0 {
		t.Fatal("scan of a missing root found pairs")
	}
}

func TestCategoryRange(t *testing.T) {
	for level, want := range map[string][2]int{
		"s0-s0:c0.c767": {0, 767}, "s0": {0, 1023}, "s0-s0:c5": {5, 5}, "s0-s0:junk": {0, 1023},
	} {
		if lo, hi := categoryRange(level); lo != want[0] || hi != want[1] {
			t.Errorf("%s: %d..%d", level, lo, hi)
		}
	}
}

func TestMCSAllocatorAvoidsForeignPairs(t *testing.T) {
	a := NewMCSAllocator(0, 3) // 6 pairs
	foreign := map[[2]int]ForeignProc{{0, 1}: {PID: 1}, {2, 3}: {PID: 2}, {5, 900}: {PID: 3}}
	a.Foreign = func() map[[2]int]ForeignProc { return foreign }
	got := map[string]bool{}
	for range 4 {
		p, err := a.Allocate()
		if err != nil {
			t.Fatal(err)
		}
		if p == "c0,c1" || p == "c2,c3" || got[p] {
			t.Fatalf("allocated %s (have %v)", p, got)
		}
		got[p] = true
	}
	if _, err := a.Allocate(); err != ErrMCSExhausted {
		t.Fatalf("want ErrMCSExhausted with the rest held by others, got %v", err)
	}
	// A container ended: its pair is free again.
	delete(foreign, [2]int{0, 1})
	if p, err := a.Allocate(); err != nil || p != "c0,c1" {
		t.Fatalf("got %s %v", p, err)
	}
}

func TestCollisions(t *testing.T) {
	var stopped []string
	s := &Systemd{MCS: NewMCSAllocator(768, 1023), stop: func(i *unitInstance) { stopped = append(stopped, i.name) }}
	s.live = map[[2]int]*unitInstance{
		{800, 801}: {name: "mcp-fs-a.service", mcs: "c800,c801", s: s},
		{802, 900}: {name: "mcp-fs-b.service", mcs: "c802,c900", s: s},
	}
	scan := MCSScan{Pairs: map[[2]int]ForeignProc{{800, 801}: {PID: 42, Context: "system_u:system_r:container_t:s0:c800,c801"}}}
	hits := s.Collisions(scan)
	if len(hits) != 1 || hits[0].Instance != "mcp-fs-a.service" || hits[0].Foreign.PID != 42 {
		t.Fatalf("hits %+v", hits)
	}
	if len(stopped) != 1 || stopped[0] != "mcp-fs-a.service" {
		t.Fatalf("stopped %v", stopped)
	}
}
