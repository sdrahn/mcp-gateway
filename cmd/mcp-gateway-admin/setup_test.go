package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// With the deprecated -config, setup http edits that file: it writes the
// http block with -write, and only shows what it would change without.
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
	if !strings.Contains(stderr.String(), "-config is deprecated and goes away in 1.5") {
		t.Errorf("no deprecation warning: %s", stderr.String())
	}
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

// setupArgs are the answers of a setup on dir, against the fake gateway g.
func setupArgs(g *fakeGateway, dir string) []string {
	return []string{"setup", "http", "-socket", g.sock, "-timeout", "1s",
		"-url", "https://127.0.0.1:1/mcp", "-issuer", "https://127.0.0.1:1/realms/mcp",
		"-cert", filepath.Join(dir, "cert.pem"), "-key", filepath.Join(dir, "key.pem"), "-scopes", "mcp"}
}

// setup http sets only the keys it changes, in the drop-in config set
// writes, over the block in force; gateway.yaml stays as it is, and
// config unset takes a key out again.
func TestSetupHTTPDropIn(t *testing.T) {
	base := baseFile(t, "version: 1\nsocket_group: mcp-users\nhttp:\n  issuer: https://old.example/realms/mcp\n")
	baseData, _ := os.ReadFile(base)
	g := newFakeGateway(t, base)
	target := filepath.Join(g.dir, adminDropIn)
	args := setupArgs(g, t.TempDir())

	var stdout, stderr bytes.Buffer
	run(args, &stdout, &stderr)
	out := stdout.String()
	if !strings.Contains(out, "not written yet: run again with -write to set in "+target) ||
		!strings.Contains(out, "http.issuer: https://127.0.0.1:1/realms/mcp (was https://old.example/realms/mcp), set in "+base+" (line 4)") ||
		strings.Contains(stderr.String(), "deprecated") {
		t.Errorf("dry run:\n%s%s", out, stderr.String())
	}
	if _, err := os.Stat(target); err == nil {
		t.Error("the dry run wrote the drop-in")
	}

	stdout.Reset()
	run(append(args, "-write"), &stdout, &stderr)
	if out := stdout.String(); !strings.Contains(out, "wrote "+target) || !strings.Contains(out, "in force") {
		t.Errorf("write:\n%s%s", out, stderr.String())
	}
	data, _ := os.ReadFile(target)
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc) != 1 || !strings.Contains(string(data), "config unset removes keys again") {
		t.Fatalf("drop-in: %v\n%s", err, data)
	}
	h, _ := doc["http"].(map[string]any)
	if h["listen"] != ":1" || h["issuer"] != "https://127.0.0.1:1/realms/mcp" || h["audience"] != "https://127.0.0.1:1/mcp" ||
		fmt.Sprint(h["scopes"]) != "[mcp]" || h["groups_claim"] != nil {
		t.Errorf("http in the drop-in: %v\n%s", h, data)
	}
	if now, _ := os.ReadFile(base); !bytes.Equal(now, baseData) {
		t.Errorf("gateway.yaml changed:\n%s", now)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", fi.Mode())
	}
	stdout.Reset()
	run(append(args, "-write"), &stdout, &stderr)
	if !strings.Contains(stdout.String(), "the configuration in force has this http block") {
		t.Errorf("again:\n%s", stdout.String())
	}

	if rc, out, errs := g.run(t, "unset", "http.listen"); rc != 0 || !strings.Contains(out, "http.listen is in force") {
		t.Errorf("unset: %d %s%s", rc, out, errs)
	}
	if g, _, _ := config.ResolveWith([]string{base}, g.dir); g.HTTP.Listen != "" || g.HTTP.Audience != "https://127.0.0.1:1/mcp" {
		t.Errorf("after unset: %+v", g.HTTP)
	}
}

// A later drop-in that sets one of the keys would win: nothing is written.
func TestSetupHTTPLaterDropIn(t *testing.T) {
	base := baseFile(t, "version: 1\n")
	g := newFakeGateway(t, base)
	later := filepath.Join(g.dir, "60-site.yaml")
	if err := os.WriteFile(later, []byte("version: 1\nhttp:\n  issuer: https://site.example/realms/mcp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if rc := run(append(setupArgs(g, t.TempDir()), "-write"), &stdout, &stderr); rc != 1 ||
		!strings.Contains(stdout.String(), later+" sets http.issuer too (line 3) and is read after") {
		t.Errorf("rc %d:\n%s%s", rc, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(g.dir, adminDropIn)); err == nil {
		t.Error("written all the same")
	}
}
