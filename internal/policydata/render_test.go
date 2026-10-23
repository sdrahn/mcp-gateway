package policydata

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRender(t *testing.T) {
	src, out, shipped := t.TempDir(), filepath.Join(t.TempDir(), "rbac"), t.TempDir()
	// The top in YAML, its JSON ignored; a subdirectory (chapter 12); one
	// without role data; a file OPA loaded before; the rendering of 1.6,
	// in JSON.
	writeFile(t, filepath.Join(src, "data.yaml"), "# who may do what\nroles:\n  tester:\n    permissions:\n      - {server: fs, tool: 'read_*'}\nbindings:\n  users: {alice: [tester, nope]}\n")
	writeFile(t, filepath.Join(src, "data.json"), `{"roles": {"old": {"permissions": []}}}`)
	writeFile(t, filepath.Join(src, "managers", "data.yaml"), "alice: bob\n")
	writeFile(t, filepath.Join(src, "empty", "README"), "nothing")
	writeFile(t, filepath.Join(src, "extra.json"), `{"x": 1}`)
	writeFile(t, filepath.Join(out, "data.json"), `{"roles": {"old": {"permissions": []}}}`)

	p, err := PlanRender(src, "", shipped)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sources) != 2 || p.Sources[0].Rel != "." || p.Sources[0].File != filepath.Join(src, "data.yaml") ||
		!slices.Equal(p.Sources[0].Ignored, []string{filepath.Join(src, "data.json")}) ||
		p.Sources[1].Rel != "managers" {
		t.Errorf("sources %+v", p.Sources)
	}
	// The schema's findings are reported, the data rendered all the same.
	if len(p.Problems) != 1 || !strings.Contains(p.Problems[0], `unknown role "nope"`) {
		t.Errorf("problems %q", p.Problems)
	}
	if !slices.Equal(p.Unloaded, []string{filepath.Join(src, "extra.json")}) || len(p.JSON) != 0 {
		t.Errorf("unloaded %q, JSON %q", p.Unloaded, p.JSON)
	}

	// Rendered as data.yaml (OPA ignores *.json from 1.7), the rendering
	// of 1.6 removed.
	written, removed, err := p.Render(out)
	if err != nil || !slices.Equal(written, []string{"data.yaml", "managers/data.yaml"}) || !slices.Equal(removed, []string{"data.json"}) {
		t.Fatalf("render: %v %v %v", written, removed, err)
	}
	if got := strings.Join(strings.Fields(readFile(t, filepath.Join(out, "data.yaml"))), ""); got !=
		`{"roles":{"tester":{"permissions":[{"server":"fs","tool":"read_*"}]}},"bindings":{"users":{"alice":["tester","nope"]}}}` {
		t.Errorf("rendered %s", got)
	}
	if got := strings.Join(strings.Fields(readFile(t, filepath.Join(out, "managers", "data.yaml"))), ""); got != `{"alice":"bob"}` {
		t.Errorf("managers %s", got)
	}
	if fi, err := os.Stat(filepath.Join(out, "data.yaml")); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v %v", fi, err)
	}

	// Nothing changed: nothing written (OPA does not reload).
	if w, r, err := p.Render(out); err != nil || len(w) != 0 || len(r) != 0 {
		t.Errorf("again: %v %v %v", w, r, err)
	}

	// The subdirectory gone: its rendering removed, the directory too.
	if err := os.RemoveAll(filepath.Join(src, "managers")); err != nil {
		t.Fatal(err)
	}
	p, err = PlanRender(src, "", shipped)
	if err != nil {
		t.Fatal(err)
	}
	if w, r, err := p.Stale(out); err != nil || len(w) != 0 || !slices.Equal(r, []string{"managers/data.yaml"}) {
		t.Errorf("stale: %v %v %v", w, r, err)
	}
	if _, removed, err := p.Render(out); err != nil || !slices.Equal(removed, []string{"managers/data.yaml"}) {
		t.Errorf("removed %v %v", removed, err)
	}
	if _, err := os.Stat(filepath.Join(out, "managers")); !os.IsNotExist(err) {
		t.Errorf("managers/ left: %v", err)
	}
	entries, _ := os.ReadDir(out)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".render-") {
			t.Errorf("temporary file left: %s", e.Name())
		}
	}
}

// A file that does not parse renders nothing: the last rendering stays.
func TestRenderBroken(t *testing.T) {
	src, out := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(src, "data.yaml"), "roles: {}\n")
	p, err := PlanRender(src, "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Render(out); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, file, content, err string }{
		{"YAML", "data.yaml", "roles: {}\nroles: {}\n", `line 2: key "roles" is already defined`},
		{"in a subdirectory", "sub/data.yaml", "a: [", "sub/data.yaml: yaml: line 1"},
		{"not an object", "data.yaml", "- a\n- b\n", "not an object"},
	} {
		writeFile(t, filepath.Join(src, tc.file), tc.content)
		if _, err := PlanRender(src, "", t.TempDir()); err == nil || !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.err)
		}
	}
	if got := readFile(t, filepath.Join(out, "data.yaml")); strings.Join(strings.Fields(got), "") != `{"roles":{}}` {
		t.Errorf("last rendering: %s", got)
	}
}

// Role data in JSON is no longer read (since 1.7): a data.json without a
// data.yaml is reported, renders nothing, and keeps the shipped default
// out of force; what was rendered from it before is removed, so the
// policy has no role data from it (it fails closed).
func TestRenderJSON(t *testing.T) {
	src, out := t.TempDir(), t.TempDir()
	def := filepath.Join(t.TempDir(), "data.yaml")
	writeFile(t, def, "roles: {shipped: {}}\n")
	writeFile(t, filepath.Join(src, "data.yaml"), "roles: {mine: {}}\n")
	writeFile(t, filepath.Join(src, "managers", "data.yaml"), "alice: bob\n")
	p, err := PlanRender(src, def, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Render(out); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"data.yaml", "managers/data.yaml"} {
		if err := os.Remove(filepath.Join(src, f)); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(src, strings.TrimSuffix(f, ".yaml")+".json"), "{}")
	}
	p, err = PlanRender(src, def, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(src, "data.json"), filepath.Join(src, "managers", "data.json")}
	if len(p.Sources) != 0 || !slices.Equal(p.JSON, want) {
		t.Errorf("sources %+v, JSON %q", p.Sources, p.JSON)
	}
	if _, removed, err := p.Render(out); err != nil || !slices.Equal(removed, []string{"data.yaml", "managers/data.yaml"}) {
		t.Errorf("removed %v %v", removed, err)
	}
}

// No role data: nothing rendered, and what was rendered is removed.
func TestRenderNone(t *testing.T) {
	out := t.TempDir()
	writeFile(t, filepath.Join(out, "data.json"), `{"roles": {}}`)
	p, err := PlanRender(filepath.Join(t.TempDir(), "missing"), "", t.TempDir())
	if err != nil || len(p.Sources) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	if _, removed, err := p.Render(out); err != nil || !slices.Equal(removed, []string{"data.json"}) {
		t.Errorf("%v %v", removed, err)
	}
}

// Where the administrator's directory has no role data, the shipped
// default is in force, taken whole: a role data file of theirs replaces
// it, and a subdirectory of theirs is rendered beside it.
func TestRenderDefault(t *testing.T) {
	src, out := filepath.Join(t.TempDir(), "rbac"), t.TempDir()
	def := filepath.Join(t.TempDir(), "data.yaml")
	writeFile(t, def, "# shipped\nroles:\n  viewer: {permissions: []}\n  admin: {permissions: []}\n")

	for _, tc := range []struct{ name, setup, want string }{
		{"no directory", "", `{"roles":{"viewer":{"permissions":[]},"admin":{"permissions":[]}}}`},
		{"an empty directory", "mkdir", `{"roles":{"viewer":{"permissions":[]},"admin":{"permissions":[]}}}`},
		{"the administrator's data.yaml, taken whole", "data.yaml", `{"roles":{"mine":{"permissions":[]}}}`},
	} {
		switch tc.setup {
		case "mkdir":
			if err := os.MkdirAll(filepath.Join(src, "managers"), 0o755); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(src, "managers", "data.yaml"), "alice: bob\n")
		case "data.yaml":
			writeFile(t, filepath.Join(src, "data.yaml"), `{"roles": {"mine": {"permissions": []}}}`)
		}
		p, err := PlanRender(src, def, "")
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(p.Sources) == 0 || p.Sources[0].Rel != "." {
			t.Fatalf("%s: %+v", tc.name, p.Sources)
		}
		wantFile := def
		if tc.setup == "data.yaml" {
			wantFile = filepath.Join(src, "data.yaml")
		}
		if p.Sources[0].File != wantFile {
			t.Errorf("%s: in force %s, want %s", tc.name, p.Sources[0].File, wantFile)
		}
		if _, _, err := p.Render(out); err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(strings.Fields(readFile(t, filepath.Join(out, "data.yaml"))), ""); got != tc.want {
			t.Errorf("%s: rendered %s", tc.name, got)
		}
		if tc.setup != "" {
			if got := strings.Join(strings.Fields(readFile(t, filepath.Join(out, "managers", "data.yaml"))), ""); got != `{"alice":"bob"}` {
				t.Errorf("%s: managers %q", tc.name, got)
			}
		}
	}
	// A default that does not parse is an error, as the administrator's is.
	writeFile(t, def, "roles: [\n")
	if err := os.Remove(filepath.Join(src, "data.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanRender(src, def, ""); err == nil {
		t.Error("broken default rendered")
	}
}
