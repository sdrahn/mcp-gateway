package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/doctor"
)

func TestDoctorUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := runDoctor([]string{"extra"}, &out, &errb); rc != 2 {
		t.Errorf("extra argument: rc %d", rc)
	}
	if rc := runDoctor([]string{"-h"}, &out, &errb); rc != 0 || !strings.Contains(errb.String(), "usage: mcp-gateway-admin doctor") {
		t.Errorf("-h: rc %d, %s", rc, errb.String())
	}
}

// Without a running gateway and without root: the configuration and the
// role data are checked, the rest fails or is skipped.
func TestDoctorOffline(t *testing.T) {
	dir := t.TempDir()
	servers := filepath.Join(dir, "servers.d")
	if err := os.MkdirAll(servers, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("servers.d/sys.yaml", "name: sys\ncommand: [/usr/bin/true]\nrun_as: mcp-nobody-has-rules\n")
	cfg := write("gateway.yaml", "servers_dir: "+servers+"\nvendor_servers_dir: "+filepath.Join(dir, "none")+
		"\npolicy:\n  opa_socket: "+filepath.Join(dir, "opa.sock")+"\napprovals:\n  control_socket: "+filepath.Join(dir, "control.sock")+"\n")
	rbac := write("data.json", `{"roles": {"r": {"permissions": []}}, "bindings": {"users": {"alice": ["nope"]}}}`)

	var out, errb bytes.Buffer
	rc := runDoctor([]string{"-config", cfg, "-policy-data", rbac, "-shipped-policy", "", "-no-start", "-json"}, &out, &errb)
	if rc != 1 {
		t.Errorf("rc %d, want 1 (failures); stderr %s", rc, errb.String())
	}
	var rs []doctor.Result
	if err := json.Unmarshal(out.Bytes(), &rs); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	got := map[string]doctor.Result{}
	for _, r := range rs {
		got[r.Check] = r
	}
	if r := got["configuration"]; r.Status != doctor.OK || !strings.Contains(r.Summary, "1 servers (sys)") {
		t.Errorf("configuration: %+v", r)
	}
	if r := got["role data"]; r.Status != doctor.Fail || !strings.Contains(strings.Join(r.Details, "\n"), "nope") {
		t.Errorf("role data: %+v", r)
	}
	if r := got["gateway status"]; r.Status != doctor.Fail {
		t.Errorf("gateway status: %+v", r)
	}
	if r := got["policy"]; r.Status != doctor.Fail && r.Status != doctor.Skip {
		t.Errorf("policy: %+v", r)
	}
	if r := got["servers"]; r.Status != doctor.Skip {
		t.Errorf("servers: %+v", r)
	}
	if r := got["polkit mcp-nobody-has-rules"]; r.Status != doctor.Warn {
		t.Errorf("polkit: %+v", r)
	}

	// An unknown -server stops after the configuration.
	out.Reset()
	if rc := runDoctor([]string{"-config", cfg, "-server", "nope", "-json"}, &out, &errb); rc != 1 || !strings.Contains(out.String(), "not in the registry") {
		t.Errorf("-server nope: rc %d, %s", rc, out.String())
	}
}

// Roles naming missing tools are reported with the server's version and
// account, and the usual causes.
func TestRolesResult(t *testing.T) {
	if r := rolesResult("zypp", "0.1.0", "mcp-sysmgmt", nil); r != nil {
		t.Fatalf("no findings: %+v", r)
	}
	msgs := []string{`role zypp-reader, permission 4: zypp has no tool "plan_install"`}
	r := rolesResult("zypp", "0.1.0", "mcp-sysmgmt", msgs)
	if r == nil || r.Status != doctor.Warn || r.Summary != "1 permissions name what zypp 0.1.0 does not offer to mcp-sysmgmt" {
		t.Fatalf("result %+v", r)
	}
	all := strings.Join(r.Details, "\n")
	for _, want := range []string{msgs[0], "only to root", "another version", "mcp-gateway-admin inspect -server zypp"} {
		if !strings.Contains(all, want) {
			t.Errorf("details lack %q:\n%s", want, all)
		}
	}
	// A root server hides nothing from itself; no version, principal.
	r = rolesResult("fs", "", "root", msgs)
	if strings.Contains(strings.Join(r.Details, "\n"), "only to root") || r.Summary != "1 permissions name what fs does not offer to root" {
		t.Errorf("root: %+v", r)
	}
	if r = rolesResult("fs", "", "principal", msgs); !strings.HasSuffix(r.Summary, "to the discovery account") {
		t.Errorf("principal: %q", r.Summary)
	}
}
