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
		g.Supervisor.Mode != "systemd" || g.Supervisor.SELinux != "auto" || g.ApprovalTimeout != DefaultApprovalTimeout {
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

func TestLoadGatewayErrors(t *testing.T) {
	tests := map[string]string{
		"unknown field":   "sockett: /run/x.sock\n",
		"relative socket": "socket: mcp.sock\n",
		"http no tls":     "http:\n  listen: ':8443'\n  issuer: x\n  audience: y\n",
		"http no issuer":  "http:\n  listen: ':8443'\n  cert_file: c\n  key_file: k\n",
		"bad mode":        "supervisor:\n  mode: docker\n",
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

func TestLoadBackendsErrors(t *testing.T) {
	tests := map[string][]string{
		"bad name":         {"name: Bad_Name\ncommand: [/usr/bin/a]\n"},
		"relative command": {"name: a\ncommand: [a]\n"},
		"empty command":    {"name: a\n"},
		"bad selinux type": {"name: a\ncommand: [/usr/bin/a]\nselinux_type: unconfined_t\n"},
		"bad isolation":    {"name: a\ncommand: [/usr/bin/a]\nisolation: global\n"},
		"bad protect_home": {"name: a\ncommand: [/usr/bin/a]\nsandbox:\n  protect_home: maybe\n"},
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
