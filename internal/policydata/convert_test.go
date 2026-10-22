package policydata

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func decode(t *testing.T, data []byte) any {
	t.Helper()
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("%v: %s", err, data)
	}
	return v
}

func TestToYAML(t *testing.T) {
	in := `{"version": 1, "roles": {"z": {"description": "a: b, c # d", "permissions": [
		{"server": "*", "tool": "read_*", "args": {"path": "^${home}/"}},
		{"server": "fs", "tool": "write_file", "require_approval": true, "approval_scopes": ["once", "1h"]}]},
		"yes": {"description": "yes", "permissions": []}},
		"bindings": {"users": {"1000": ["z"], "on": ["no", "null", "true", "~", "0x10", "1e3"]}, "groups": {}},
		"x": [1.5, -2, null, false, "", "multi\nline", "{brace}", "[bracket]", "- dash", "&anchor", "*alias", "!tag"]}`
	y, err := ToYAML([]byte(in), "a header\nof two lines")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(y), "# a header\n# of two lines\n") {
		t.Errorf("header:\n%s", y)
	}
	back, err := ToJSON(y)
	if err != nil {
		t.Fatalf("%v:\n%s", err, y)
	}
	if !reflect.DeepEqual(decode(t, back), decode(t, []byte(in))) {
		t.Errorf("round trip:\n%s\n%s", y, back)
	}
	// Keys in their order.
	if v, r, b := strings.Index(string(y), "\nversion:"), strings.Index(string(y), "\nroles:"), strings.Index(string(y), "\nbindings:"); v < 0 || v > r || r > b {
		t.Errorf("order:\n%s", y)
	}
	for _, bad := range []string{`{"a": `, `{"a": 1} {}`, `[1, 2`} {
		if _, err := ToYAML([]byte(bad), ""); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// shippedRoleFiles are the role data files the packages ship.
func shippedRoleFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, g := range []string{"../../policy/mcp/rbac/data.*", "../../profiles/*/roles.*", "../../packaging/*/*-roles.*", "../../examples/dev/rbac/data.*"} {
		m, err := filepath.Glob(g)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) < 10 {
		t.Fatalf("shipped role files: %v", files)
	}
	return files
}

// The shipped role files convert to YAML and back to the same data.
func TestToYAMLShipped(t *testing.T) {
	for _, f := range shippedRoleFiles(t) {
		_, data, _, err := Read(f)
		if err != nil {
			t.Fatal(err)
		}
		y, err := ToYAML(data, "")
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		back, err := ToJSON(y)
		if err != nil || !reflect.DeepEqual(decode(t, back), decode(t, data)) {
			t.Errorf("%s: %v\n%s", f, err, y)
		}
	}
}

// OPA reads the shipped YAML files (the setups' roles, which it loads from
// /usr/share/mcp-gateway/policy itself) as the same data as ToJSON does:
// its YAML parser resolves some plain scalars differently (yes, on).
// Needs opa (OPA=path, else on PATH).
func TestShippedYAMLAsOPAReadsIt(t *testing.T) {
	opa := os.Getenv("OPA")
	if opa == "" {
		var err error
		if opa, err = exec.LookPath("opa"); err != nil {
			t.Skip("no opa")
		}
	}
	check := func(name string, y []byte) {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "data.yaml"), y, 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(opa, "eval", "--format", "raw", "--data", "x:"+dir, "json.marshal(data.x)").Output()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		mine, err := ToJSON(y)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(decode(t, bytes.TrimSpace(out)), decode(t, mine)) {
			t.Errorf("%s: OPA reads\n%s\nToJSON\n%s", name, out, mine)
		}
	}
	for _, f := range shippedRoleFiles(t) {
		y, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Ext(f) == ".json" {
			if y, err = ToYAML(y, ""); err != nil {
				t.Fatal(err)
			}
		}
		check(f, y)
	}
	// What ToYAML writes for the scalars YAML 1.1 reads otherwise.
	y, err := ToYAML([]byte(`{"a": ["yes", "no", "on", "off", "y", "n", "true", "null", "~", "0x10", "010", "1e3", ".inf", "2026-01-01", "12:30"]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	check("ambiguous scalars", y)
}
