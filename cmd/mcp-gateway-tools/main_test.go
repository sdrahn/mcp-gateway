package main

import (
	"bytes"
	"strings"
	"testing"
)

// Each command answers -h with its usage under mcp-gateway-admin.
func TestCommands(t *testing.T) {
	for name := range commands {
		var stdout, stderr bytes.Buffer
		run([]string{name, "-h"}, &stdout, &stderr)
		if got := stdout.String() + stderr.String(); !strings.Contains(got, "usage: mcp-gateway-admin "+name) {
			t.Errorf("%s -h: %s", name, got)
		}
	}
	var stdout, stderr bytes.Buffer
	if rc := run([]string{"doctor"}, &stdout, &stderr); rc != 2 || !strings.Contains(stderr.String(), `unknown command "doctor"`) {
		t.Errorf("doctor: %d %s", rc, stderr.String())
	}
}
