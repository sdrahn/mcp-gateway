package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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

// sameData reports whether two files hold the same data (YAML or JSON).
func sameData(t *testing.T, a, b string) bool {
	t.Helper()
	var va, vb any
	for _, f := range []struct {
		path string
		v    *any
	}{{a, &va}, {b, &vb}} {
		raw, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatal(err)
		}
		j, err := policydata.ToJSON(raw)
		if err != nil {
			t.Fatalf("%s: %v", f.path, err)
		}
		if err := json.Unmarshal(j, f.v); err != nil {
			t.Fatal(err)
		}
	}
	return reflect.DeepEqual(va, vb)
}

// The data of custom Rego (below the policy directory, not below rbac):
// OPA loads it itself and refuses the same data twice, so the source goes
// once the conversion is written, either way. OPA reads the YAML as the
// JSON it was.
func TestPolicyConvertCustomData(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "policy")
	limits := filepath.Join(policy, "limits")
	if err := os.MkdirAll(limits, 0o755); err != nil {
		t.Fatal(err)
	}
	js := filepath.Join(limits, "data.json")
	orig := `{"limits": {"fs": {"calls": 10, "note": "yes", "on": true, "ids": ["010", "1e3", "2026-01-01"]}}, "empty": {}}`
	if err := os.WriteFile(js, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := filepath.Join(t.TempDir(), "orig.json")
	if err := os.WriteFile(saved, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		rc := runPolicy(append(args, "--policy-data", filepath.Join(policy, "rbac", "data.json")), &out, &errb)
		return rc, out.String(), errb.String()
	}
	opaData := func() any {
		t.Helper()
		opa, err := exec.LookPath("opa")
		if err != nil {
			return nil
		}
		out, err := exec.Command(opa, "eval", "--format", "raw", "--ignore", "rbac", "--data", "mcp:"+policy, "json.marshal(data.mcp)").Output()
		if err != nil {
			t.Fatalf("opa: %v", err)
		}
		var v any
		if err := json.Unmarshal(bytes.TrimSpace(out), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	before := opaData()

	yml := filepath.Join(limits, "data.yaml")
	rc, out, errs := run("convert", js)
	if rc != 0 || !strings.Contains(out, "wrote "+yml) || !strings.Contains(out, "removed "+js+": OPA loads every data file below "+policy) ||
		!strings.Contains(out, "policy convert --to json "+yml+" brings it back") {
		t.Fatalf("convert: %d %s %s", rc, out, errs)
	}
	if _, err := os.Stat(js); !os.IsNotExist(err) {
		t.Errorf("%s still there", js)
	}
	if y, _ := os.ReadFile(yml); !strings.HasPrefix(string(y), "# Policy data, converted from data.json") {
		t.Errorf("YAML:\n%s", y)
	}
	if !sameData(t, yml, saved) {
		t.Error("YAML differs from the JSON")
	}
	if after := opaData(); !reflect.DeepEqual(before, after) {
		t.Errorf("OPA reads\n%v\nnow, before\n%v", after, before)
	}
	files, err := policydata.JSONFiles(policy, filepath.Join(policy, "rbac"))
	if err != nil || len(files) != 0 {
		t.Errorf("JSON left: %v %v", files, err)
	}

	// Back, for an earlier release.
	rc, out, errs = run("convert", "--to", "json", yml)
	if rc != 0 || !strings.Contains(out, "wrote "+js) || !strings.Contains(out, "removed "+yml) || !strings.Contains(out, "policy convert "+js+" brings") {
		t.Fatalf("--to json: %d %s %s", rc, out, errs)
	}
	if !sameData(t, js, saved) {
		t.Error("JSON differs from the original")
	}
	if after := opaData(); !reflect.DeepEqual(before, after) {
		t.Errorf("OPA reads\n%v\nafter --to json, before\n%v", after, before)
	}
	// Elsewhere: nothing removed.
	other := filepath.Join(t.TempDir(), "x.yaml")
	if rc, _, errs := run("convert", js, "-o", other); rc != 0 {
		t.Fatalf("-o: %d %s", rc, errs)
	}
	if _, err := os.Stat(js); err != nil {
		t.Errorf("-o elsewhere removed %s", js)
	}
}

// --to json: role data back to JSON for an earlier release; data.yaml
// stays in force while it exists.
func TestPolicyConvertToJSON(t *testing.T) {
	rbac := filepath.Join(t.TempDir(), "policy", "rbac")
	if err := os.MkdirAll(rbac, 0o755); err != nil {
		t.Fatal(err)
	}
	yml := filepath.Join(rbac, "data.yaml")
	if err := os.WriteFile(yml, []byte("# why\nroles:\n  r: {permissions: [{server: fs}]}  # fs only\nbindings: {users: {alice: [r]}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		rc := runPolicy(append(args, "--policy-data", filepath.Join(rbac, "data.json")), &out, &errb)
		return rc, out.String(), errb.String()
	}
	js := filepath.Join(rbac, "data.json")
	rc, out, errs := run("convert", "--to", "json")
	if rc != 0 || !strings.Contains(out, "wrote "+js) || !strings.Contains(out, yml+" stays in force while it exists; to go back to 1.4 or earlier") {
		t.Fatalf("--to json: %d %s %s", rc, out, errs)
	}
	if _, err := os.Stat(yml); err != nil {
		t.Errorf("role data's YAML removed: %v", err)
	}
	b, _ := os.ReadFile(js)
	if !json.Valid(b) || !strings.HasPrefix(string(b), "{\n  \"roles\": {") || !sameData(t, js, yml) {
		t.Errorf("JSON:\n%s", b)
	}
	// And back again: the same data.
	back := filepath.Join(t.TempDir(), "back.yaml")
	if rc, _, errs := run("convert", js, "-o", back); rc != 0 || !sameData(t, back, yml) {
		t.Errorf("round trip: %d %s", rc, errs)
	}
	if rc, _, errs := run("convert", "--to", "json"); rc != exitRefused || !strings.Contains(errs, "exists; --force replaces it") {
		t.Errorf("again: %d %s", rc, errs)
	}
	if rc, _, errs := run("convert", "--to", "json", js); rc != exitRefused || !strings.Contains(errs, "is JSON already") {
		t.Errorf("JSON: %d %s", rc, errs)
	}
	if rc, _, errs := run("convert", "--to", "toml"); rc != exitRefused || !strings.Contains(errs, "--to is yaml or json") {
		t.Errorf("--to toml: %d %s", rc, errs)
	}
}
