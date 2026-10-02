package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

// The top-level help names every command, and each command answers -h
// with its own usage.
func TestUsageListsCommands(t *testing.T) {
	fs := flag.NewFlagSet("mcp-gateway", flag.ContinueOnError)
	fs.Bool("check", false, "validate the configuration")
	var out bytes.Buffer
	usage(&out, fs)
	for _, c := range commands {
		if !strings.Contains(out.String(), "\n  "+c.name+" ") {
			t.Errorf("usage does not list %s:\n%s", c.name, out.String())
		}
	}
	if !strings.Contains(out.String(), "-check") {
		t.Errorf("usage lacks the gateway's options:\n%s", out.String())
	}

	for _, c := range commands {
		var stdout, stderr bytes.Buffer
		runHelp([]string{c.name}, &stdout, &stderr, fs)
		if got := stdout.String() + stderr.String(); !strings.Contains(got, "usage: mcp-gateway "+c.name) {
			t.Errorf("help %s: %s", c.name, got)
		}
	}

	var stdout, stderr bytes.Buffer
	if rc := runHelp([]string{"nope"}, &stdout, &stderr, fs); rc != 2 || !strings.Contains(stderr.String(), `unknown command "nope"`) {
		t.Errorf("help nope: %d %s", rc, stderr.String())
	}
}
