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
	if err := checkPolicyData(log, path, true); err == nil || !strings.Contains(err.Error(), "data.json: 1 problem(s)") {
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
	write("data.yaml", "roles: {}\nroles: {}\n")
	if err := checkPolicyData(log, path, true); err == nil || !strings.Contains(err.Error(), `data.yaml: line 2: key "roles" is already defined`) {
		t.Errorf("broken YAML: %v", err)
	}
	if err := checkPolicyData(log, filepath.Join(t.TempDir(), "data.json"), false); err != nil {
		t.Errorf("missing, not required: %v", err)
	}
}
