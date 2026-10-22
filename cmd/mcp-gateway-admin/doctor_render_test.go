package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/doctor"
	"github.com/sdrahn/mcp-gateway/internal/policydata"
)

// The doctor checks the role data in force and names the file it
// ignores; it compares the role data with what OPA has (the rendering)
// and names files OPA no longer loads.
func TestDoctorRendering(t *testing.T) {
	dir := t.TempDir()
	rbac := filepath.Join(dir, "policy", "rbac")
	write := func(name, content string) {
		t.Helper()
		p := filepath.Join(rbac, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d := &doctorRun{policyData: filepath.Join(rbac, "data.json"), rendered: filepath.Join(dir, "run", "rbac")}
	details := func(r doctor.Result) string { return strings.Join(r.Details, "\n") }

	write("data.json", `{"roles": {}}`)
	if r := d.roleData(); r.Status != doctor.OK || !strings.Contains(r.Summary, "data.json valid") {
		t.Errorf("JSON alone: %+v", r)
	}
	if r := d.rendering(); r.Status != doctor.Fail || !strings.Contains(r.Summary, "OPA has no role data") ||
		!strings.Contains(details(r), "systemctl restart mcp-policy-render.service") {
		t.Errorf("not rendered: %+v", r)
	}

	write("data.yaml", "# YAML now\nroles: {}\n")
	r := d.roleData()
	if r.Status != doctor.Warn || !strings.Contains(r.Summary, "data.yaml valid") ||
		!strings.Contains(details(r), filepath.Join(rbac, "data.json")+" is ignored: "+filepath.Join(rbac, "data.yaml")+" is in force") {
		t.Errorf("both: %+v", r)
	}
	render := func() {
		t.Helper()
		p, err := policydata.PlanRender(rbac, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := p.Render(d.rendered); err != nil {
			t.Fatal(err)
		}
	}
	render()
	if r := d.rendering(); r.Status != doctor.OK || !strings.Contains(r.Summary, "is current") {
		t.Errorf("rendered: %+v", r)
	}

	write("data.yaml", "roles: {r: {permissions: []}}\n")
	write("managers/data.json", `{"alice": "bob"}`)
	if r := d.rendering(); r.Status != doctor.Warn || !strings.Contains(details(r), "not current: "+filepath.Join(d.rendered, "data.json")) ||
		!strings.Contains(details(r), "not current: "+filepath.Join(d.rendered, "managers", "data.json")) {
		t.Errorf("stale: %+v", r)
	}
	render()
	write("custom.rego", "package mcp.custom\n")
	if r := d.rendering(); r.Status != doctor.Warn || !strings.Contains(details(r), filepath.Join(rbac, "custom.rego")+" is not loaded") ||
		!strings.Contains(details(r), "a rule belongs in "+filepath.Join(dir, "policy")) {
		t.Errorf("unloaded: %+v", r)
	}

	write("data.yaml", "roles: {}\nroles: {}\n")
	if r := d.roleData(); r.Status != doctor.Fail || !strings.Contains(r.Summary, `line 2: key "roles" is already defined`) ||
		!strings.Contains(details(r), "OPA keeps the role data it had") {
		t.Errorf("broken: %+v", r)
	}
}

// The doctor names each file of the local policy in JSON with the command
// that converts it (deprecated since 1.6), and is content once all is YAML.
func TestDoctorJSONFiles(t *testing.T) {
	policy := filepath.Join(t.TempDir(), "policy")
	write := func(name, content string) string {
		t.Helper()
		p := filepath.Join(policy, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	d := &doctorRun{policyData: filepath.Join(policy, "rbac", "data.json")}
	if r := d.jsonFiles(); r.Status != doctor.OK || !strings.Contains(r.Summary, "none") {
		t.Errorf("no policy files: %+v", r)
	}
	role := write("rbac/data.json", `{"roles": {}}`)
	custom := write("limits/data.json", `{"limits": {}}`)
	r := d.jsonFiles()
	if r.Status != doctor.Warn || !strings.Contains(r.Summary, "2 file(s) in JSON, deprecated since 1.6") ||
		strings.Join(r.Details, "\n") != custom+": mcp-gateway-admin policy convert "+custom+"\n"+role+": mcp-gateway-admin policy convert "+role {
		t.Errorf("JSON: %+v", r)
	}
	rs := []doctor.Result{r}
	doctor.Identify(rs)
	if rs[0].ID != "json-policy-data" {
		t.Errorf("id %q", rs[0].ID)
	}
	write("rbac/data.yaml", "roles: {}\n")
	if err := os.Remove(custom); err != nil {
		t.Fatal(err)
	}
	write("limits/data.yaml", "limits: {}\n")
	if r := d.jsonFiles(); r.Status != doctor.OK {
		t.Errorf("converted: %+v", r)
	}
}
