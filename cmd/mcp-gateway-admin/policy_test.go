package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/policydata"
)

func TestPolicyConvert(t *testing.T) {
	dir := t.TempDir()
	js := filepath.Join(dir, "data.json")
	if err := os.WriteFile(js, []byte(`{"roles": {"r": {"permissions": [{"server": "fs", "tool": "read_*"}]}}, "bindings": {"users": {"alice": ["r"]}}}`), 0o640); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		rc := runPolicy(args, &out, &errb)
		return rc, out.String(), errb.String()
	}
	yml := filepath.Join(dir, "data.yaml")
	rc, out, errs := run("convert", js)
	if rc != 0 || !strings.Contains(out, "wrote "+yml) || !strings.Contains(out, yml+" is in force now; "+js+" is ignored") {
		t.Fatalf("convert: %d %s %s", rc, out, errs)
	}
	y, _ := os.ReadFile(yml)
	if !strings.HasPrefix(string(y), "# Role data") || !strings.Contains(string(y), "data.json next to this file is ignored") ||
		!strings.Contains(string(y), "{server: fs, tool: read_*}") {
		t.Errorf("YAML:\n%s", y)
	}
	if fi, _ := os.Stat(yml); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", fi.Mode())
	}
	// The same data, and data.json kept.
	_, a, _, _ := policydata.Read(yml)
	b, _ := os.ReadFile(js)
	if strings.Join(strings.Fields(string(a)), "") != strings.Join(strings.Fields(string(b)), "") {
		t.Errorf("data:\n%s\n%s", a, b)
	}
	if rc, _, errs := run("convert", js); rc != exitRefused || !strings.Contains(errs, "exists; --force replaces it") {
		t.Errorf("again: %d %s", rc, errs)
	}
	if rc, _, errs := run("convert", js, "--force"); rc != 0 {
		t.Errorf("--force: %d %s", rc, errs)
	}
	if rc, out, _ := run("convert", js, "-o", "-"); rc != 0 || !strings.Contains(out, "roles:") {
		t.Errorf("-o -: %d %s", rc, out)
	}
	if rc, _, errs := run("convert", yml); rc != exitRefused || !strings.Contains(errs, "is YAML already") {
		t.Errorf("YAML: %d %s", rc, errs)
	}
	if err := os.WriteFile(js, []byte(`{"roles": `), 0o644); err != nil {
		t.Fatal(err)
	}
	if rc, _, errs := run("convert", js, "-o", filepath.Join(dir, "x.yaml")); rc != exitRefused || !strings.Contains(errs, "not valid JSON") {
		t.Errorf("broken: %d %s", rc, errs)
	}
	if rc, _, _ := run("nope"); rc != exitUsage {
		t.Errorf("usage: %d", rc)
	}
}
