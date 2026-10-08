package config

import (
	"os"
	"path/filepath"
	"testing"
)

// The setup packages' definitions load (their landlock too), each on its
// own as the packages install them; the rulesets are what chapter 13
// says.
func TestProfiles(t *testing.T) {
	files, err := filepath.Glob("../../profiles/*/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no profiles: %v", err)
	}
	withLandlock := map[string]bool{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(f)), data, 0o644); err != nil {
			t.Fatal(err)
		}
		backends, err := LoadBackends(dir)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		for _, b := range backends {
			if b.Landlock != nil {
				withLandlock[filepath.Base(f)] = true
				if b.Privileged {
					t.Errorf("%s: a privileged server with landlock", f)
				}
			}
		}
	}
	for _, f := range []string{"systemd.yaml", "firewalld.yaml", "zypp.yaml"} {
		if !withLandlock[f] {
			t.Errorf("%s has no landlock", f)
		}
	}
	for _, f := range []string{"snapper.yaml", "snapper-privileged.yaml", "zypp-privileged.yaml", "suseconnect.yaml"} {
		if withLandlock[f] {
			t.Errorf("%s has landlock (see the note in it)", f)
		}
	}
}
