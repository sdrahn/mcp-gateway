package policydata

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Where a directory has data.yaml and data.json, the YAML is in force and
// the JSON ignored, whichever of the two is named.
func TestInForce(t *testing.T) {
	dir := t.TempDir()
	yml, js := filepath.Join(dir, "data.yaml"), filepath.Join(dir, "data.json")
	check := func(name, path, want string, wantIgnored []string) {
		t.Helper()
		got, ignored := InForce(path)
		if got != want || !slices.Equal(ignored, wantIgnored) {
			t.Errorf("%s: %s %v, want %s %v", name, got, ignored, want, wantIgnored)
		}
	}
	check("neither", js, js, nil)
	if err := os.WriteFile(js, []byte(`{"roles": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	check("JSON only", js, js, nil)
	check("JSON only, YAML named", yml, js, nil)
	if err := os.WriteFile(yml, []byte("roles: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	check("both", js, yml, []string{js})
	check("both, YAML named", yml, yml, []string{js})
	other := filepath.Join(dir, "roles.json")
	check("another name", other, other, nil)
	check("standard input", "-", "-", nil)
	if err := os.Remove(yml); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(yml, 0o755); err != nil {
		t.Fatal(err)
	}
	check("YAML a directory", js, js, nil)
}

func TestRead(t *testing.T) {
	dir := t.TempDir()
	js := filepath.Join(dir, "data.json")
	if err := os.WriteFile(js, []byte(`{"roles": {"old": {}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data.yaml"), []byte("roles:\n  new: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	file, data, ignored, err := Read(js)
	if err != nil || file != filepath.Join(dir, "data.yaml") || !slices.Equal(ignored, []string{js}) ||
		strings.Join(strings.Fields(string(data)), "") != `{"roles":{"new":{}}}` {
		t.Errorf("%s %q %v %v", file, data, ignored, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data.yaml"), []byte("roles:\n  new: {}\n  new: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Read(js); err == nil || !strings.Contains(err.Error(), "data.yaml: line 3: key \"new\" is already defined") {
		t.Errorf("duplicate key: %v", err)
	}
}

func TestToJSON(t *testing.T) {
	for _, tc := range []struct{ name, in, want, err string }{
		{"empty", "", `{}`, ""},
		{"JSON", `{"roles": {"r": {"permissions": [{"server": "fs", "tool": "x"}]}}}`,
			`{"roles":{"r":{"permissions":[{"server":"fs","tool":"x"}]}}}`, ""},
		{"block style, order kept", "version: 1\nroles:\n  z: {}\n  a:\n    description: A\n",
			`{"version":1,"roles":{"z":{},"a":{"description":"A"}}}`, ""},
		{"scalars", "a: true\nb: 10\nc: 1.5\nd: null\ne: ~\nf: \"10\"\ng: 2026-01-01\nh: yes\n",
			`{"a":true,"b":10,"c":1.5,"d":null,"e":null,"f":"10","g":"2026-01-01","h":"yes"}`, ""},
		{"patterns not escaped", "args: {path: '^/srv/<x>&'}\n", `{"args":{"path":"^/srv/<x>&"}}`, ""},
		{"comments", "# roles\nroles: {} # none\n", `{"roles":{}}`, ""},
		{"anchors", "base: &b {server: fs, tool: x}\nlist: [*b]\n",
			`{"base":{"server":"fs","tool":"x"},"list":[{"server":"fs","tool":"x"}]}`, ""},
		{"number keys as strings", "users:\n  1000: [r]\n", `{"users":{"1000":["r"]}}`, ""},
		{"duplicate key", "roles: {}\nroles: {}\n", "", `line 2: key "roles" is already defined`},
		{"merge key", "base: &b {a: 1}\nx:\n  <<: *b\n", "", "line 3: merge keys (<<) are not supported"},
		{"key a mapping", "? {a: 1}\n: x\n", "", "line 1: a key must be a string"},
		{"not YAML", "roles: [\n", "", "yaml:"},
	} {
		got, err := ToJSON([]byte(tc.in))
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: %s %v, want error %q", tc.name, got, err, tc.err)
			}
			continue
		}
		if err != nil || strings.Join(strings.Fields(string(got)), "") != strings.ReplaceAll(tc.want, " ", "") {
			t.Errorf("%s: %s %v, want %s", tc.name, got, err, tc.want)
		}
	}
}

// Standard input is YAML when it is not JSON.
func TestIsYAML(t *testing.T) {
	for _, tc := range []struct {
		file, data string
		want       bool
	}{
		{"-", `{"roles": {}}`, false},
		{"-", "roles: {}\n", true},
		{"x/data.yaml", `{"roles": {}}`, true},
		{"x/data.json", "roles: {}\n", false},
	} {
		if got := isYAML(tc.file, []byte(tc.data)); got != tc.want {
			t.Errorf("%s %q: %v", tc.file, tc.data, got)
		}
	}
}

// The shipped default is in force where the directory has neither file.
func TestReadOr(t *testing.T) {
	dir := t.TempDir()
	def := filepath.Join(t.TempDir(), "data.yaml")
	if err := os.WriteFile(def, []byte("roles: {shipped: {}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	js := filepath.Join(dir, "data.json")
	if f, data, _, err := ReadOr(js, def); err != nil || f != def || !strings.Contains(string(data), "shipped") {
		t.Errorf("default: %s %s %v", f, data, err)
	}
	if f, _ := InForceOr(js, ""); f != js {
		t.Errorf("no default: %s", f)
	}
	if f, _ := InForceOr(js, filepath.Join(dir, "missing.yaml")); f != js {
		t.Errorf("missing default: %s", f)
	}
	if err := os.WriteFile(js, []byte(`{"roles": {"mine": {}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if f, data, _, err := ReadOr(js, def); err != nil || f != js || !strings.Contains(string(data), "mine") {
		t.Errorf("own: %s %s %v", f, data, err)
	}
	// Another name than data.json or data.yaml has no default.
	if f, _ := InForceOr(filepath.Join(dir, "other.json"), def); f != filepath.Join(dir, "other.json") {
		t.Errorf("other name: %s", f)
	}
}

// Role data in JSON that does not parse names the line and column, as
// YAML's errors name the line.
func TestReadJSONSyntaxError(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct{ content, want string }{
		{"{\n  \"roles\": {\n    \"dev\": {\"permissions\": [{\"server\": \"fs\"},]}\n  }\n}\n",
			"data.json: line 3, column 46: invalid character ']' looking for beginning of value"},
		{"{\"roles\": {}", "data.json: line 1, column 12: unexpected end of JSON input"},
		{"{\"roles\": {}}\n}\n", "data.json: line 2, column 1: invalid character '}' after top-level value"},
	} {
		p := filepath.Join(dir, "data.json")
		if err := os.WriteFile(p, []byte(c.content), 0o644); err != nil {
			t.Fatal(err)
		}
		_, _, _, err := Read(p)
		if err == nil || !strings.HasSuffix(err.Error(), c.want) || !strings.HasPrefix(err.Error(), p+": ") {
			t.Errorf("%q: %v, want …%s", c.content, err, c.want)
		}
	}
}
