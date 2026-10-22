package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The check reads the file in force: data.yaml before data.json, whichever
// is named, and says that the other is ignored.
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

	write("data.json", `{"roles": {}, "binding": {}}`)
	if err := checkPolicyData(log, path, true, true); err == nil || !strings.Contains(err.Error(), "data.json: 1 problem(s)") {
		t.Errorf("JSON: %v", err)
	}
	// Role data in JSON warns, deprecated since 1.6, with the command.
	write("data.json", `{"roles": {}}`)
	logs.Reset()
	if err := checkPolicyData(log, path, true, true); err != nil {
		t.Errorf("JSON: %v", err)
	}
	if out := logs.String(); !strings.Contains(out, "deprecated since 1.6") || !strings.Contains(out, `convert="mcp-gateway-admin policy convert `+path+`"`) {
		t.Errorf("JSON warning: %s", out)
	}
	logs.Reset()
	if err := checkPolicyData(log, path, true, false); err != nil || strings.Contains(logs.String(), "deprecated") {
		t.Errorf("without deprecations: %v, %s", err, logs.String())
	}
	write("data.yaml", "# comments are fine\nroles: {}\n")
	logs.Reset()
	if err := checkPolicyData(log, path, true, true); err != nil {
		t.Errorf("YAML in force: %v", err)
	}
	if out := logs.String(); strings.Contains(out, "deprecated") || !strings.Contains(out, "role data ignored") || !strings.Contains(out, `"role data valid" path=`+filepath.Join(dir, "data.yaml")) {
		t.Errorf("logs: %s", out)
	}
	write("data.yaml", "roles: {}\nroles: {}\n")
	if err := checkPolicyData(log, path, true, true); err == nil || !strings.Contains(err.Error(), `data.yaml: line 2: key "roles" is already defined`) {
		t.Errorf("broken YAML: %v", err)
	}
	if err := checkPolicyData(log, filepath.Join(t.TempDir(), "data.json"), false, true); err != nil {
		t.Errorf("missing, not required: %v", err)
	}
}

// At start and with --check, the gateway warns about every file of the
// local policy in JSON: role data in force and custom data.
func TestWarnJSON(t *testing.T) {
	policy := t.TempDir()
	for _, f := range []string{"rbac/data.json", "rbac/team/data.yaml", "custom/data.json"} {
		p := filepath.Join(policy, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	warnJSON(log, filepath.Join(policy, "rbac", "data.json"))
	out := logs.String()
	for _, f := range []string{"rbac/data.json", "custom/data.json"} {
		p := filepath.Join(policy, f)
		if !strings.Contains(out, "path="+p) || !strings.Contains(out, `convert="mcp-gateway-admin policy convert `+p+`"`) {
			t.Errorf("no warning about %s: %s", f, out)
		}
	}
	if strings.Contains(out, "team") || strings.Count(out, "deprecated since 1.6") != 2 {
		t.Errorf("warnings: %s", out)
	}
	logs.Reset()
	warnJSON(log, "-")
	warnJSON(log, "")
	if logs.Len() != 0 {
		t.Errorf("standard input or none: %s", logs.String())
	}
}
