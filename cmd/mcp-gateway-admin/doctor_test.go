package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
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
	write("servers.d/sys.yaml", "name: sys\ncommand: [/usr/bin/true]\nrun_as: mcp-nobody-has-rules\nselinux_type: mcpsrv_systemd_t\n")
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
	if r := got["polkit mcp-nobody-has-rules"]; r.Status != doctor.Warn || r.ID != "polkit" || r.Subject != "mcp-nobody-has-rules" {
		t.Errorf("polkit: %+v", r)
	}

	// -server checks only that server: no gateway, OPA, state or
	// principal checks; the configuration and the role data only if
	// they fail (here the role data does).
	out.Reset()
	if rc := runDoctor([]string{"-config", cfg, "-policy-data", rbac, "-shipped-policy", "", "-no-start", "-json", "-server", "sys"}, &out, &errb); rc != 1 {
		t.Errorf("-server sys: rc %d, want 1 (the role data fails)", rc)
	}
	rs = nil
	if err := json.Unmarshal(out.Bytes(), &rs); err != nil {
		t.Fatalf("-server: %v: %s", err, out.String())
	}
	var checks []string
	for _, r := range rs {
		checks = append(checks, r.Check)
		switch {
		case r.Check == "configuration", r.Check == "gateway status", r.Check == "policy", r.Check == "state files",
			r.Check == "principals", strings.HasSuffix(r.Check, ".service"):
			t.Errorf("-server sys ran %q: %+v", r.Check, r)
		}
	}
	if !slices.Contains(checks, "role data") || !slices.Contains(checks, "polkit mcp-nobody-has-rules") {
		t.Errorf("-server sys: %v", checks)
	}
	write("data.json", `{"roles": {"r": {"permissions": []}}, "bindings": {"users": {}}}`)
	out.Reset()
	runDoctor([]string{"-config", cfg, "-policy-data", rbac, "-shipped-policy", "", "-no-start", "-json", "-server", "sys"}, &out, &errb)
	if strings.Contains(out.String(), `"role data"`) {
		t.Errorf("-server sys shows valid role data: %s", out.String())
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
	for _, want := range []string{msgs[0], "only to root", "another version", "mcp-gateway-admin inspect --server zypp"} {
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

// Denials count from -since ago, but not from before the current boot
// unless asked.
func TestDenialWindow(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	boot := now.Add(-2 * time.Hour)
	from, label := denialWindow(now, 24*time.Hour, boot, false)
	if !from.Equal(boot) || !strings.Contains(label, "the current boot") {
		t.Errorf("after a reboot: %v %q", from, label)
	}
	if from, label = denialWindow(now, 24*time.Hour, boot, true); !from.Equal(now.Add(-24*time.Hour)) || strings.Contains(label, "boot") {
		t.Errorf("previous boots: %v %q", from, label)
	}
	if from, _ = denialWindow(now, time.Hour, boot, false); !from.Equal(now.Add(-time.Hour)) {
		t.Errorf("window within the boot: %v", from)
	}
	if from, _ = denialWindow(now, time.Hour, time.Time{}, false); !from.Equal(now.Add(-time.Hour)) {
		t.Errorf("boot unknown: %v", from)
	}
	if b := bootTime(); b.IsZero() || b.After(time.Now()) {
		t.Errorf("bootTime: %v", b)
	}
}

func TestGatewayStatus(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "control.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var body atomic.Value
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body.Load().(string))
	})}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })

	body.Store(`{"version": "0.9.0", "restart_pending": false}`)
	if r := gatewayStatus(sock); r.Status != doctor.OK || r.Summary != "running version 0.9.0" {
		t.Errorf("%+v", r)
	}
	body.Store(`{"version": "0.9.0", "restart_pending": false, "servers_error": "/etc/mcp-gateway/servers.d/web.yaml: unknown key netwrok"}`)
	if r := gatewayStatus(sock); r.Status != doctor.Warn || !strings.Contains(r.Summary, "serves the previous ones") ||
		r.Details[0] != "/etc/mcp-gateway/servers.d/web.yaml: unknown key netwrok" {
		t.Errorf("%+v", r)
	}
	body.Store(`{"version": "0.10.0", "config_error": "/etc/mcp-gateway/gateway.yaml: yaml: line 3", "restart_needed": ["socket_group", "http.listen"]}`)
	if r := gatewayStatus(sock); r.Status != doctor.Warn || !strings.Contains(r.Summary, "gateway.yaml not reloaded") ||
		!strings.Contains(r.Summary, "next start") || r.Details[2] != "changed since the start: socket_group, http.listen" {
		t.Errorf("%+v", r)
	}
}

// A definition that does not load fails the configuration check, and the
// other checks still run: the running gateway keeps its definitions.
func TestDoctorBrokenDefinition(t *testing.T) {
	dir := t.TempDir()
	servers := filepath.Join(dir, "servers.d")
	if err := os.MkdirAll(servers, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(servers, "web.yaml"), []byte("name: web\ncommand: [/opt/web]\nnetwrok: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(cfg, []byte("servers_dir: "+servers+"\nvendor_servers_dir: "+filepath.Join(dir, "none")+
		"\napprovals:\n  control_socket: "+filepath.Join(dir, "control.sock")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	runDoctor([]string{"-config", cfg, "-policy-data", "", "-shipped-policy", "", "-no-start", "-json"}, &out, &errb)
	var rs []doctor.Result
	if err := json.Unmarshal(out.Bytes(), &rs); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	got := map[string]doctor.Result{}
	for _, r := range rs {
		got[r.Check] = r
	}
	if r := got["configuration"]; r.Status != doctor.Fail || !strings.Contains(r.Summary, "netwrok") {
		t.Errorf("configuration: %+v", r)
	}
	if _, ok := got["gateway status"]; !ok {
		t.Errorf("the checks stopped after the configuration: %+v", rs)
	}
}

func TestDoctorExit(t *testing.T) {
	ok, warn, fail := doctor.Result{Status: doctor.OK}, doctor.Result{Status: doctor.Warn}, doctor.Result{Status: doctor.Fail}
	for _, c := range []struct {
		rs     []doctor.Result
		strict bool
		want   int
	}{
		{[]doctor.Result{ok}, true, 0},
		{[]doctor.Result{ok, warn}, false, 0},
		{[]doctor.Result{ok, warn}, true, 3},
		{[]doctor.Result{warn, fail}, true, 1},
		{[]doctor.Result{fail}, false, 1},
	} {
		if got := doctorExit(c.rs, c.strict); got != c.want {
			t.Errorf("%+v strict=%v: %d, want %d", c.rs, c.strict, got, c.want)
		}
	}
}

// With approval mail on, each approver group is looked up as the mail
// does it: a group that does not exist warns, one with members is OK.
func TestDoctorApproverGroups(t *testing.T) {
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("no getent")
	}
	d := &doctorRun{root: true, gw: &config.Gateway{StateDir: t.TempDir()},
		rbac: []byte(`{"approvers": {"default": ["self", "group:root"], "fs": ["group:no-such-group-mcpgw", "user:alice"]}}`)}
	if rs := d.approverGroups(); rs != nil {
		t.Fatalf("mail off: %+v", rs)
	}
	d.gw.Notifications.Email.SMTP = "localhost:25"
	rs := d.approverGroups()
	if len(rs) != 2 || rs[0].Check != "approver group no-such-group-mcpgw" || rs[0].Status != doctor.Warn ||
		rs[1].Check != "approver group root" || rs[1].Status != doctor.OK {
		t.Fatalf("%+v", rs)
	}
	doctor.Identify(rs)
	if rs[1].ID != "approver-group" || rs[1].Subject != "root" {
		t.Errorf("%+v", rs[1])
	}
}
