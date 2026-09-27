package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadGatewayDefaults(t *testing.T) {
	p := writeFile(t, t.TempDir(), "gateway.yaml", "{}\n")
	g, err := LoadGateway(p)
	if err != nil {
		t.Fatal(err)
	}
	if g.Socket != DefaultSocket || g.Policy.OPASocket != DefaultOPASocket || g.Policy.Timeout != DefaultPolicyTimeout ||
		g.Supervisor.Mode != "systemd" || g.Supervisor.SELinux != "auto" || g.ApprovalTimeout != DefaultApprovalTimeout ||
		g.Supervisor.IdleTimeout != DefaultIdleTimeout ||
		g.Approvals.ControlSocket != DefaultControl || g.Policy.WatchInterval != DefaultWatchInterval {
		t.Errorf("defaults not applied: %+v", g)
	}
}

func TestLoadGatewayShippedExample(t *testing.T) {
	g, err := LoadGateway("../../config/gateway.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if g.Policy.Timeout != 250*time.Millisecond {
		t.Errorf("policy.timeout = %v", g.Policy.Timeout)
	}
}

func TestLoadGatewayHTTP(t *testing.T) {
	p := writeFile(t, t.TempDir(), "gateway.yaml", `http:
  listen: ":8443"
  cert_file: c
  key_file: k
  issuer: http://127.0.0.1:9000/realms/mcp
  audience: https://gw.example.com:8443/mcp
  scopes: [mcp]
`)
	g, err := LoadGateway(p)
	if err != nil {
		t.Fatal(err)
	}
	if g.HTTP.GroupsClaim != "groups" || g.HTTP.SessionIdleTimeout != DefaultHTTPSessionIdle || g.HTTP.Scopes[0] != "mcp" {
		t.Errorf("http = %+v", g.HTTP)
	}
}

func TestLoadGatewayErrors(t *testing.T) {
	tests := map[string]string{
		"unknown field":   "sockett: /run/x.sock\n",
		"relative socket": "socket: mcp.sock\n",
		"http no tls":     "http:\n  listen: ':8443'\n  issuer: x\n  audience: y\n",
		"http no issuer":  "http:\n  listen: ':8443'\n  cert_file: c\n  key_file: k\n",
		"mtls no ca":      "http:\n  listen: ':8443'\n  cert_file: c\n  key_file: k\n  issuer: x\n  audience: y\n  client_auth: required\n",
		"bound no mtls":   "http:\n  listen: ':8443'\n  cert_file: c\n  key_file: k\n  issuer: x\n  audience: y\n  require_bound_tokens: true\n",
		"bad client auth": "http:\n  listen: ':8443'\n  cert_file: c\n  key_file: k\n  issuer: x\n  audience: y\n  client_auth: maybe\n  client_ca_file: ca.pem\n",
		"bad mode":        "supervisor:\n  mode: docker\n",
		"fast watch":      "policy:\n  watch_interval: 10ms\n",
		"bad audit":       "audit:\n  kernel: maybe\n",
		"url no id":       "approvals:\n  url_template: https://h/approve\n",
		"url plain":       "approvals:\n  url_template: http://h.example.com/{id}\n",
		"relative ctl":    "approvals:\n  control_socket: ctl.sock\n",
		"http issuer url": "http:\n  listen: ':8443'\n  cert_file: c\n  key_file: k\n  issuer: idp\n  audience: https://gw/mcp\n",
		"http plain aud":  "http:\n  listen: ':8443'\n  cert_file: c\n  key_file: k\n  issuer: https://idp\n  audience: http://gw.example.com/mcp\n",
		"bad selinux":     "supervisor:\n  selinux: maybe\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			p := writeFile(t, t.TempDir(), "gateway.yaml", content)
			if _, err := LoadGateway(p); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestLoadBackendsShippedExamples(t *testing.T) {
	bs, err := LoadBackends("../../config/servers.d")
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) == 0 {
		t.Fatal("no backends loaded")
	}
	for name, b := range bs {
		if b.Name != name {
			t.Errorf("key %q != name %q", name, b.Name)
		}
	}
}

func TestLoadBackendsDefaults(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", "name: a\ncommand: [/usr/bin/a]\n")
	bs, err := LoadBackends(dir)
	if err != nil {
		t.Fatal(err)
	}
	b := bs["a"]
	if b.SELinuxType != DefaultSELinuxType || b.Isolation != IsolationPrincipal ||
		b.RunAs != DefaultRunAs || b.Sandbox.ProtectHome != DefaultProtectHome || b.Network {
		t.Errorf("defaults not applied: %+v", b)
	}
}

func TestLoadBackendsVendorOverrideMask(t *testing.T) {
	vendor, admin := t.TempDir(), t.TempDir()
	writeFile(t, vendor, "fs.yaml", "name: fs\ncommand: [/usr/libexec/mcp-servers/fs]\n")
	writeFile(t, vendor, "git.yaml", "name: git\ncommand: [/usr/libexec/mcp-servers/git]\n")
	writeFile(t, vendor, "db.yaml", "name: db\ncommand: [/usr/libexec/mcp-servers/db]\n")
	// Override fs, mask git (empty file) and db (symlink to /dev/null), add local.
	writeFile(t, admin, "fs.yaml", "name: fs\ncommand: [/opt/fs]\nnetwork: true\n")
	writeFile(t, admin, "git.yaml", "")
	if err := os.Symlink("/dev/null", filepath.Join(admin, "db.yaml")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, admin, "local.yaml", "name: local\ncommand: [/usr/local/bin/local]\n")

	bs, err := LoadBackends(vendor, admin, filepath.Join(admin, "missing"))
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) != 2 || bs["fs"] == nil || bs["local"] == nil {
		t.Fatalf("backends %v", bs)
	}
	if bs["fs"].Command[0] != "/opt/fs" || !bs["fs"].Network {
		t.Errorf("fs not overridden: %+v", bs["fs"])
	}
}

func TestParseCredentials(t *testing.T) {
	b := &Backend{Credentials: []string{"github-token", "db:/srv/secrets/db.pass"}}
	cs, err := b.ParseCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 2 || cs[0] != (Credential{"github-token", DefaultCredentialsDir + "/github-token"}) ||
		cs[1] != (Credential{"db", "/srv/secrets/db.pass"}) {
		t.Fatalf("credentials %+v", cs)
	}
}

func TestResolveExplicitMissing(t *testing.T) {
	if _, _, err := Resolve(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for a missing explicit config")
	}
}

func TestLoadBackendsErrors(t *testing.T) {
	tests := map[string][]string{
		"bad name":         {"name: Bad_Name\ncommand: [/usr/bin/a]\n"},
		"relative command": {"name: a\ncommand: [a]\n"},
		"empty command":    {"name: a\n"},
		"bad selinux type": {"name: a\ncommand: [/usr/bin/a]\nselinux_type: unconfined_t\n"},
		"bad isolation":    {"name: a\ncommand: [/usr/bin/a]\nisolation: global\n"},
		"bad protect_home": {"name: a\ncommand: [/usr/bin/a]\nsandbox:\n  protect_home: maybe\n"},
		"bad cred name":    {"name: a\ncommand: [/usr/bin/a]\ncredentials: [\"../x\"]\n"},
		"relative cred":    {"name: a\ncommand: [/usr/bin/a]\ncredentials: [\"db:secrets/db\"]\n"},
		"unclean cred":     {"name: a\ncommand: [/usr/bin/a]\ncredentials: [\"db:/etc/../root/x\"]\n"},
		"dup cred":         {"name: a\ncommand: [/usr/bin/a]\ncredentials: [db, \"db:/x\"]\n"},
		"duplicate":        {"name: a\ncommand: [/usr/bin/a]\n", "name: a\ncommand: [/usr/bin/b]\n"},
	}
	for name, files := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for i, content := range files {
				writeFile(t, dir, strings.Repeat("x", i+1)+".yaml", content)
			}
			if _, err := LoadBackends(dir); err == nil {
				t.Error("expected error")
			}
		})
	}
}
