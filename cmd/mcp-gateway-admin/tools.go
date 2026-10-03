package main

import (
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/sdrahn/mcp-gateway/internal/version"
)

// toolsProgram has the onboarding commands; the package mcp-gateway-tools
// installs it in LIBEXECDIR/mcp-gateway.
const toolsProgram = "mcp-gateway-tools"

// findTools returns mcp-gateway-tools: next to this program (bin/ of a
// checkout), else where the package installs it.
func findTools() (string, error) {
	if self, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(self), toolsProgram)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	p := filepath.Join(version.LibexecDir, "mcp-gateway", toolsProgram)
	_, err := os.Stat(p)
	return p, err
}

// tool returns the command that runs "mcp-gateway-tools name".
func tool(name string) func(args []string, stdout, stderr io.Writer) int {
	return func(args []string, _, stderr io.Writer) int {
		path, err := findTools()
		if err != nil {
			sayf(stderr, "mcp-gateway-admin: %s is in the package mcp-gateway-tools, which is not installed (%s)", name, path)
			return 1
		}
		// Exec, so that signals reach the command itself (profile restores
		// the domain it made permissive when interrupted).
		err = syscall.Exec(path, append([]string{path, name}, args...), os.Environ())
		sayf(stderr, "mcp-gateway-admin: running %s: %v", path, err)
		return 1
	}
}
