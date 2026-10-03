package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

// The help names the gateway's options and mcp-gateway-admin; unknown
// commands are refused.
func TestUsage(t *testing.T) {
	fs := flag.NewFlagSet("mcp-gateway", flag.ContinueOnError)
	fs.Bool("check", false, "validate the configuration")
	var out bytes.Buffer
	usage(&out, fs)
	for _, want := range []string{"-check", "mcp-gateway-admin (doctor, inspect"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("usage lacks %q:\n%s", want, out.String())
		}
	}

	var stdout, stderr bytes.Buffer
	if rc := runHelp([]string{"nope"}, &stdout, &stderr, fs); rc != 2 || !strings.Contains(stderr.String(), `unknown command "nope"`) {
		t.Errorf("help nope: %d %s", rc, stderr.String())
	}
}

// The commands that moved to mcp-gateway-admin in 0.7 are unknown, and
// the error names their replacement.
func TestMovedCommands(t *testing.T) {
	fs := flag.NewFlagSet("mcp-gateway", flag.ContinueOnError)
	for old, sub := range movedCommands {
		var stderr bytes.Buffer
		if rc := runHelp([]string{old}, &stderr, &stderr, fs); rc != 2 ||
			!strings.Contains(stderr.String(), `"mcp-gateway-admin `+sub+`" since 0.7`) {
			t.Errorf("%s: %d %s", old, rc, stderr.String())
		}
	}
}
