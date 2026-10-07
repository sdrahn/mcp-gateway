package syscmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A program outside PATH is found in Dirs; a missing one says where it
// was looked for.
func TestPath(t *testing.T) {
	dir := t.TempDir()
	prog := filepath.Join(dir, "matchpathcon")
	if err := os.WriteFile(prog, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plain"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "/nonexistent")
	old := Dirs
	Dirs = []string{dir}
	t.Cleanup(func() { Dirs = old })

	if p, err := Path("matchpathcon"); err != nil || p != prog {
		t.Errorf("outside PATH: %q %v", p, err)
	}
	for _, name := range []string{"plain", "absent"} {
		if _, err := Path(name); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
