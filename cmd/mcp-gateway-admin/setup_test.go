package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// setup http writes the http block with -write, and only shows what it
// would change without.
func TestSetupHTTPWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n# keep me\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	args := []string{"setup", "http", "-config", path, "-timeout", "1s",
		"-url", "https://127.0.0.1:1/mcp", "-issuer", "https://127.0.0.1:1/realms/mcp",
		"-cert", filepath.Join(dir, "cert.pem"), "-key", filepath.Join(dir, "key.pem"), "-scopes", "mcp"}

	var stdout, stderr bytes.Buffer
	rc := run(args, &stdout, &stderr)
	if rc != 1 || !strings.Contains(stdout.String(), "not written yet: run again with -write") || !strings.Contains(stdout.String(), "http.audience: https://127.0.0.1:1/mcp") {
		t.Errorf("dry run: %d\n%s%s", rc, stdout.String(), stderr.String())
	}
	if g, _ := config.LoadGateway(path); g.HTTP.Listen != "" {
		t.Error("the dry run wrote the configuration")
	}

	stdout.Reset()
	run(append(args, "-write"), &stdout, &stderr)
	if !strings.Contains(stdout.String(), "wrote "+path) || !strings.Contains(stdout.String(), "systemctl restart mcp-gateway.service") {
		t.Errorf("write:\n%s%s", stdout.String(), stderr.String())
	}
	g, err := config.LoadGateway(path)
	if err != nil || g.HTTP.Listen != ":1" || g.HTTP.Scopes[0] != "mcp" {
		t.Fatalf("written: %v %+v", err, g)
	}
	if data, _ := os.ReadFile(path); !strings.Contains(string(data), "# keep me") {
		t.Errorf("comment lost:\n%s", data)
	}
	// The identity provider is not there: the check says so.
	if !strings.Contains(stdout.String(), "Identity provider") && !strings.Contains(stdout.String(), "identity provider") {
		t.Errorf("no identity provider check:\n%s", stdout.String())
	}
}

func TestSetupUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if rc := run([]string{"setup"}, &stdout, &stderr); rc != 2 || !strings.Contains(stderr.String(), "usage: mcp-gateway-admin setup http") {
		t.Errorf("setup: %d %s", rc, stderr.String())
	}
	stderr.Reset()
	if rc := run([]string{"setup", "http", "-url", "https://gw/mcp", "-config", filepath.Join(t.TempDir(), "none.yaml")}, &stdout, &stderr); rc != 2 || !strings.Contains(stderr.String(), "not set yet: http.issuer (-issuer)") {
		t.Errorf("missing answers: %d %s", rc, stderr.String())
	}
}
