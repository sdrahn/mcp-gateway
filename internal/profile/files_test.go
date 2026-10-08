package profile

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The sampler sees the files a process has open, with their mode, and
// its working directory.
func TestSample(t *testing.T) {
	dir := t.TempDir()
	r, err := os.Create(filepath.Join(dir, "r"))
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	rf, err := os.Open(filepath.Join(dir, "r"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rf.Close() }()
	wf, err := os.Create(filepath.Join(dir, "w"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wf.Close() }()
	s := NewSampler()
	s.Sample("/proc", []int{os.Getpid()})
	seen := s.Seen()
	if seen[filepath.Join(dir, "r")] != UseRead || seen[filepath.Join(dir, "w")]&UseWrite == 0 || s.Samples != 1 {
		t.Errorf("seen %v", seen)
	}
	exe, _ := os.Executable()
	if seen[exe]&UseExec == 0 {
		t.Errorf("the mapped program %s: %v", exe, seen[exe])
	}
	for p := range seen {
		if !strings.HasPrefix(p, "/") {
			t.Errorf("not a path: %q", p)
		}
	}
}

// Paths become trees beyond the base: a file its directory, nested trees
// with no more use dropped, the base's own left out except for writes it
// does not allow.
func TestDraftLandlock(t *testing.T) {
	dirs := map[string]bool{"/srv/data": true, "/var/lib/app": true, "/": true}
	isDir := func(p string) bool { return dirs[p] }
	used := map[string]Use{
		"/etc/app.conf":               UseRead,  // the base reads /etc
		"/etc/app/state.db":           UseWrite, // but does not write it
		"/usr/lib64/libc.so.6":        UseExec,
		"/proc/self/status":           UseRead,
		"/tmp/x":                      UseWrite,
		"/srv/data":                   UseRead,
		"/srv/data/sub/file":          UseRead, // inside /srv/data
		"/var/lib/app":                UseWrite,
		"/var/lib/app/cache/c":        UseRead, // inside a written tree
		"/opt/tool/bin/helper":        UseExec,
		"/home/alice/.config/app.ini": UseRead,
		"/memfd:x":                    UseRead,
		"/":                           UseRead, // the working directory
		"/top.txt":                    UseRead, // a file in /: its tree would be /
	}
	r := DraftLandlock(used, isDir)
	want := map[string][]string{
		"read":  {"/home/alice/.config", "/srv/data"},
		"write": {"/etc/app", "/var/lib/app"},
		"exec":  {"/opt/tool/bin"},
	}
	for k, got := range map[string][]string{"read": r.Read, "write": r.Write, "exec": r.Exec} {
		if !slices.Equal(got, want[k]) {
			t.Errorf("%s: %v, want %v", k, got, want[k])
		}
	}
}

func TestDenialUses(t *testing.T) {
	u := DenialUses([]Denial{
		{Path: "/var/lib/app/db", Perms: []string{"read", "open"}},
		{Path: "/var/lib/app/db", Perms: []string{"write"}},
		{Path: "/opt/x", Perms: []string{"execute"}},
		{Path: "name-only", Perms: []string{"read"}},
	})
	if u["/var/lib/app/db"] != UseRead|UseWrite || u["/opt/x"] != UseRead|UseExec || len(u) != 2 {
		t.Errorf("%v", u)
	}
}
