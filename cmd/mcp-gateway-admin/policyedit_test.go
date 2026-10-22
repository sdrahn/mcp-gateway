package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type policyOut struct {
	File     string          `json:"file"`
	Origin   string          `json:"origin"`
	Ignored  []string        `json:"ignored"`
	Data     json.RawMessage `json:"data"`
	YAML     string          `json:"yaml"`
	Error    string          `json:"error"`
	Written  bool            `json:"written"`
	Problems []string        `json:"problems"`
}

// policy show and write as Cockpit's role editor uses them: the file in
// force as JSON, and changes written to data.yaml with its comments.
func TestPolicyShowWrite(t *testing.T) {
	dir := t.TempDir()
	rbac := filepath.Join(dir, "rbac")
	if err := os.MkdirAll(rbac, 0o755); err != nil {
		t.Fatal(err)
	}
	def := filepath.Join(dir, "default.yaml")
	if err := os.WriteFile(def, []byte("# shipped\nroles:\n  viewer: {permissions: []}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := stdin
	t.Cleanup(func() { stdin = saved })
	run := func(input string, args ...string) (int, policyOut, string) {
		t.Helper()
		stdin = strings.NewReader(input)
		var out, errb bytes.Buffer
		rc := runPolicy(append(args, "-policy-data", filepath.Join(rbac, "data.json"), "-default-policy-data", def,
			"-shipped-policy", filepath.Join(dir, "none")), &out, &errb)
		var po policyOut
		if out.Len() > 0 {
			if err := json.Unmarshal(out.Bytes(), &po); err != nil {
				t.Fatalf("%v: %s", err, out.String())
			}
		}
		return rc, po, errb.String()
	}
	compact := func(b []byte) string { return strings.Join(strings.Fields(string(b)), "") }

	// The shipped default in force.
	rc, po, _ := run("", "show")
	if rc != 0 || po.Origin != "default" || po.File != def || compact(po.Data) != `{"roles":{"viewer":{"permissions":[]}}}` ||
		!strings.Contains(po.YAML, "# shipped") {
		t.Fatalf("show default: %d %+v", rc, po)
	}
	// Saving starts data.yaml from the data.
	rc, po, _ = run(`{"roles": {"viewer": {"permissions": []}}, "bindings": {"users": {"alice": ["viewer"]}}}`, "write")
	yml := filepath.Join(rbac, "data.yaml")
	if rc != 0 || !po.Written || po.File != yml || len(po.Ignored) != 0 || !strings.Contains(po.YAML, "started from "+def) {
		t.Fatalf("write from default: %d %+v", rc, po)
	}
	// The administrator comments it; a change from the page keeps that.
	b, _ := os.ReadFile(yml)
	commented := strings.Replace(string(b), "  users:", "  # who is who: ticket 42\n  users:", 1)
	if err := os.WriteFile(yml, []byte(commented), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(yml, 0o640); err != nil {
		t.Fatal(err)
	}
	rc, po, _ = run("", "show")
	if rc != 0 || po.Origin != "yaml" || !strings.Contains(po.YAML, "ticket 42") {
		t.Fatalf("show yaml: %d %+v", rc, po)
	}
	rc, po, _ = run(`{"roles": {"viewer": {"permissions": []}}, "bindings": {"users": {"alice": ["viewer"], "bob": ["viewer"]}}}`, "write")
	b, _ = os.ReadFile(yml)
	if rc != 0 || !po.Written || !strings.Contains(string(b), "# who is who: ticket 42") || !strings.Contains(string(b), "bob: [viewer]") {
		t.Fatalf("write keeps comments: %d %+v\n%s", rc, po, b)
	}
	if fi, _ := os.Stat(yml); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", fi.Mode())
	}
	// Data the schema refuses is not written, and the problems are named.
	rc, po, _ = run(`{"roles": {}, "binding": {}}`, "write")
	b2, _ := os.ReadFile(yml)
	if rc != exitRefused || po.Written || len(po.Problems) == 0 || !strings.Contains(po.Problems[0], "'binding' not allowed") || string(b2) != string(b) {
		t.Errorf("refused: %d %+v", rc, po)
	}
	// Raw YAML from the raw editor: checked, then written as it is.
	raw := "# all mine\nroles:\n  viewer: {permissions: []}  # kept\n"
	rc, po, _ = run(raw, "write", "--yaml", "--dry-run")
	if b3, _ := os.ReadFile(yml); rc != 0 || po.Written || compact(po.Data) != `{"roles":{"viewer":{"permissions":[]}}}` || string(b3) != string(b) {
		t.Errorf("dry run: %d %+v", rc, po)
	}
	rc, po, _ = run(raw, "write", "--yaml")
	if b3, _ := os.ReadFile(yml); rc != 0 || !po.Written || string(b3) != raw {
		t.Errorf("raw YAML: %d %+v\n%s", rc, po, b3)
	}
	if rc, po, _ = run("roles: {}\nroles: {}\n", "write", "--yaml"); rc != exitRefused || !strings.Contains(strings.Join(po.Problems, " "), "already defined") {
		t.Errorf("broken YAML: %d %+v", rc, po)
	}
	// data.json next to it: still ignored, and named.
	if err := os.WriteFile(filepath.Join(rbac, "data.json"), []byte(`{"roles": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rc, po, _ = run(`{"roles": {}}`, "write")
	if rc != 0 || len(po.Ignored) != 1 || !strings.HasSuffix(po.Ignored[0], "data.json") {
		t.Errorf("ignored: %d %+v", rc, po)
	}
	// data.json alone: shown converted, saving writes data.yaml beside it.
	if err := os.Remove(yml); err != nil {
		t.Fatal(err)
	}
	rc, po, _ = run("", "show")
	if rc != 0 || po.Origin != "json" || !strings.Contains(po.YAML, "roles: {}") {
		t.Errorf("show json: %d %+v", rc, po)
	}
	// A file in force that does not parse is shown as text, with the error.
	if err := os.WriteFile(yml, []byte("roles: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rc, po, _ = run("", "show")
	if rc != 0 || po.Error == "" || po.YAML != "roles: [\n" || string(po.Data) != "null" {
		t.Errorf("show broken: %d %+v", rc, po)
	}
}
