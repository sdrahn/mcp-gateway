package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/syscmd"
)

// The policy's label comes from matchpathcon also where PATH lacks the
// sbin directory it is in (the gateway-admin server's PATH); without it
// and restorecon, the error says where they were looked for and which
// packages have them.
func TestPolicyTypeOutsidePath(t *testing.T) {
	sbin := t.TempDir()
	target := filepath.Join(t.TempDir(), "prog")
	if err := os.WriteFile(target, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "/nonexistent")
	old := syscmd.Dirs
	syscmd.Dirs = []string{sbin}
	t.Cleanup(func() { syscmd.Dirs = old })

	if _, err := policyType(target); err == nil || !strings.Contains(err.Error(), "matchpathcon: not found") ||
		!strings.Contains(err.Error(), "selinux-tools") || !strings.Contains(err.Error(), "policycoreutils") {
		t.Fatalf("without the tools: %v", err)
	}

	script := "#!/bin/sh\necho 'system_u:object_r:mcpsrv_fs_exec_t:s0'\n"
	if err := os.WriteFile(filepath.Join(sbin, "matchpathcon"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, err := policyType(target); err != nil || got != "mcpsrv_fs_exec_t" {
		t.Fatalf("matchpathcon in sbin: %q %v", got, err)
	}
}
