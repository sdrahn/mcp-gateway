package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/version"
)

// The help names every command, and each command of this program
// answers -h with its own usage.
func TestUsageListsCommands(t *testing.T) {
	var out bytes.Buffer
	usage(&out)
	for _, c := range commands {
		if !strings.Contains(out.String(), "\n  "+c.name+" ") {
			t.Errorf("usage does not list %s:\n%s", c.name, out.String())
		}
	}
	for _, name := range []string{"doctor", "serve", "setup"} {
		var stdout, stderr bytes.Buffer
		run([]string{"help", name}, &stdout, &stderr)
		if got := stdout.String() + stderr.String(); !strings.Contains(got, "usage: mcp-gateway-admin "+name) {
			t.Errorf("help %s: %s", name, got)
		}
	}
	var stdout, stderr bytes.Buffer
	if rc := run([]string{"nope"}, &stdout, &stderr); rc != 2 || !strings.Contains(stderr.String(), `unknown command "nope"`) {
		t.Errorf("nope: %d %s", rc, stderr.String())
	}
	if rc := run(nil, &stdout, &stderr); rc != 2 {
		t.Errorf("no command: %d", rc)
	}
}

// Without mcp-gateway-tools, its commands say which package has them.
func TestToolsMissing(t *testing.T) {
	defer func(d string) { version.LibexecDir = d }(version.LibexecDir)
	version.LibexecDir = t.TempDir()
	for _, name := range []string{"inspect", "profile", "review"} {
		var stdout, stderr bytes.Buffer
		if rc := run([]string{name, "-h"}, &stdout, &stderr); rc != 1 ||
			!strings.Contains(stderr.String(), name+" is in the package mcp-gateway-tools, which is not installed") {
			t.Errorf("%s: %d %s", name, rc, stderr.String())
		}
	}
}
