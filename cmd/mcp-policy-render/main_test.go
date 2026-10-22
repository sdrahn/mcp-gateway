package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	src, out, shipped := t.TempDir(), filepath.Join(t.TempDir(), "rbac"), t.TempDir()
	args := []string{"-source", src, "-out", out, "-shipped", shipped}
	render := func(extra ...string) (int, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		rc := run(append(append([]string{}, args...), extra...), &stdout, &stderr)
		return rc, stderr.String()
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(src, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if rc, msg := render(); rc != 0 || !strings.Contains(msg, "no role data in "+src) {
		t.Errorf("none: %d %s", rc, msg)
	}
	write("data.json", `{"roles": {"old": {"permissions": []}}}`)
	write("data.yaml", "roles: {new: {permissions: []}}\nbindings: {users: {alice: [nope]}}\n")
	if rc, msg := render("-check"); rc != 1 || !strings.Contains(msg, "not current: data.json") {
		t.Errorf("check before: %d %s", rc, msg)
	}
	rc, msg := render()
	if rc != 0 || !strings.Contains(msg, "rendered data.json") ||
		!strings.Contains(msg, filepath.Join(src, "data.json")+" is ignored: "+filepath.Join(src, "data.yaml")+" is in force") ||
		!strings.Contains(msg, `warning: `+filepath.Join(src, "data.yaml")) {
		t.Errorf("render: %d %s", rc, msg)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "data.json")); !strings.Contains(string(b), `"new"`) {
		t.Errorf("rendered %s", b)
	}
	if rc, msg := render("-check"); rc != 0 || !strings.Contains(msg, out+" is current") {
		t.Errorf("check after: %d %s", rc, msg)
	}

	// Broken YAML: exit status 1, the last rendering kept.
	write("data.yaml", "roles: [\n")
	if rc, msg := render(); rc != 1 || !strings.Contains(msg, "the last rendering in "+out+" stays in force") {
		t.Errorf("broken: %d %s", rc, msg)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "data.json")); !strings.Contains(string(b), `"new"`) {
		t.Errorf("after broken %s", b)
	}

	var stdout, stderr bytes.Buffer
	if rc := run([]string{"extra"}, &stdout, &stderr); rc != 2 {
		t.Errorf("usage: %d", rc)
	}
}
