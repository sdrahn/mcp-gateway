package main

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/policydata"
)

// The check reads the file in force, data.yaml, whichever of data.yaml
// and data.json is named, and says that a data.json next to it is
// ignored. A data.json alone is no longer read (since 1.7): an error with
// the command that converts it.
func TestCheckPolicyDataInForce(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	saved := shippedPolicy
	shippedPolicy = ""
	t.Cleanup(func() { shippedPolicy = saved })
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	path := filepath.Join(dir, "data.json")

	write("data.json", `{"roles": {}}`)
	err := checkPolicyData(log, path, true)
	if !errors.Is(err, policydata.ErrJSON) || !strings.Contains(err.Error(), path+": configuration in JSON is no longer read since 1.7: convert it to YAML with mcp-gateway-admin policy convert "+path) {
		t.Errorf("JSON: %v", err)
	}
	write("data.yaml", "# comments are fine\nroles: {}\n")
	logs.Reset()
	if err := checkPolicyData(log, path, true); err != nil {
		t.Errorf("YAML in force: %v", err)
	}
	if out := logs.String(); !strings.Contains(out, "role data ignored") || !strings.Contains(out, `"role data valid" path=`+filepath.Join(dir, "data.yaml")) {
		t.Errorf("logs: %s", out)
	}
	write("data.yaml", "roles: {}\nbinding: {}\n")
	if err := checkPolicyData(log, path, true); err == nil || !strings.Contains(err.Error(), "data.yaml: 1 problem(s)") {
		t.Errorf("YAML with a problem: %v", err)
	}
	write("data.yaml", "roles: {}\nroles: {}\n")
	if err := checkPolicyData(log, path, true); err == nil || !strings.Contains(err.Error(), `data.yaml: line 2: key "roles" is already defined`) {
		t.Errorf("broken YAML: %v", err)
	}
	if err := checkPolicyData(log, filepath.Join(t.TempDir(), "data.json"), false); err != nil {
		t.Errorf("missing, not required: %v", err)
	}
}

// While a file of the local policy in JSON is left over (role data that
// would be in force, or custom data), the guard blocks the policy, names
// the files in the log and the first in its reason; once they are
// converted it decides again.
func TestJSONGuard(t *testing.T) {
	policy := t.TempDir()
	write := func(f string) string {
		t.Helper()
		p := filepath.Join(policy, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("rbac/team/data.yaml")
	var logs bytes.Buffer
	g := &jsonGuard{log: slog.New(slog.NewTextHandler(&logs, nil)), policyData: filepath.Join(policy, "rbac", "data.json")}
	if r := g.Blocked(); r != "" {
		t.Fatalf("YAML only: %q", r)
	}
	custom, role := write("custom/data.json"), write("rbac/data.json")
	g.checked = time.Time{}
	r := g.Blocked()
	if r != policydata.JSONProblem(custom)+" (and 1 more files in JSON)" {
		t.Errorf("reason: %q", r)
	}
	out := logs.String()
	for _, p := range []string{custom, role} {
		if !strings.Contains(out, "path="+p) || !strings.Contains(out, `convert="mcp-gateway-admin policy convert `+p+`"`) {
			t.Errorf("not logged: %s: %s", p, out)
		}
	}
	// The finding holds for a moment: no walk, no log line per request.
	logs.Reset()
	if g.Blocked() != r || logs.Len() != 0 {
		t.Errorf("again: %s", logs.String())
	}
	if err := os.Remove(custom); err != nil {
		t.Fatal(err)
	}
	g.checked = time.Time{}
	if r := g.Blocked(); r != policydata.JSONProblem(role) {
		t.Errorf("one left: %q", r)
	}
	if err := os.WriteFile(filepath.Join(policy, "rbac", "data.yaml"), []byte("roles: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g.checked = time.Time{}
	logs.Reset()
	if r := g.Blocked(); r != "" || !strings.Contains(logs.String(), "the policy decides again") {
		t.Errorf("converted: %q, %s", r, logs.String())
	}
	// With bundles OPA does not load the local policy: nothing blocks.
	// While OPA does not answer, the finding stays as it was.
	write("rbac/data.json")
	if err := os.Remove(filepath.Join(policy, "rbac", "data.yaml")); err != nil {
		t.Fatal(err)
	}
	inBundle, bundleErr := true, error(nil)
	g.bundles = func() (bool, error) { return inBundle, bundleErr }
	g.checked = time.Time{}
	if r := g.Blocked(); r != "" {
		t.Errorf("bundles: %q", r)
	}
	inBundle = false
	g.checked = time.Time{}
	if r := g.Blocked(); r != policydata.JSONProblem(role) {
		t.Errorf("no bundles: %q", r)
	}
	bundleErr = errors.New("opa down")
	g.checked = time.Time{}
	if r := g.Blocked(); r != policydata.JSONProblem(role) {
		t.Errorf("OPA down: %q", r)
	}
	// Without local role data (standard input, or none) nothing blocks.
	for _, p := range []string{"-", ""} {
		if r := (&jsonGuard{log: g.log, policyData: p}).Blocked(); r != "" {
			t.Errorf("%q: %q", p, r)
		}
	}
}
