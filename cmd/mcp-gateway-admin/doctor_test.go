package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
}
