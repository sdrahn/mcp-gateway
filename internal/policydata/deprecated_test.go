package policydata

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestJSONFiles(t *testing.T) {
	policy := t.TempDir()
	rbac := filepath.Join(policy, "rbac")
	write := func(rel, content string) string {
		t.Helper()
		p := filepath.Join(policy, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if files, err := JSONFiles(policy, rbac); err != nil || len(files) != 0 {
		t.Fatalf("empty: %v, %v", files, err)
	}
	if files, err := JSONFiles(filepath.Join(policy, "none"), filepath.Join(policy, "none", "rbac")); err != nil || len(files) != 0 {
		t.Fatalf("missing: %v, %v", files, err)
	}
	top := write("rbac/data.json", `{"roles": {}}`)
	// A data.json that data.yaml overrides is not read (InForce).
	write("rbac/team/data.json", `{}`)
	write("rbac/team/data.yaml", `{}`)
	sub := write("rbac/ops/data.json", `{}`)
	// Not role data, and not loaded by OPA either (--ignore rbac).
	write("rbac/notes.json", `{}`)
	custom := write("custom/data.json", `{"limits": {"x": 1}}`)
	other := write("custom/deep/extra.json", `{}`)
	write("custom/data2.yaml", `a: 1`)
	write("custom/rbac/skipped.json", `{}`)
	write("custom/rule.rego", `package mcp.custom`)
	files, err := JSONFiles(policy, rbac)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{custom, other, top, sub}
	if !reflect.DeepEqual(files, want) {
		t.Errorf("JSONFiles:\n got %v\nwant %v", files, want)
	}
	// Converted, the top's role data is no longer listed.
	write("rbac/data.yaml", `roles: {}`)
	files, _ = JSONFiles(policy, rbac)
	if reflect.DeepEqual(files, want) || len(files) != 3 {
		t.Errorf("after converting the top: %v", files)
	}
}

func TestJSONWarning(t *testing.T) {
	w := JSONWarning("/etc/mcp-gateway/policy/rbac/data.json")
	for _, s := range []string{
		"/etc/mcp-gateway/policy/rbac/data.json: ",
		"deprecated since 1.6",
		"mcp-gateway-admin policy convert /etc/mcp-gateway/policy/rbac/data.json",
	} {
		if !strings.Contains(w, s) {
			t.Errorf("%q lacks %q", w, s)
		}
	}
}
