package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// movedCommands are the subcommands mcp-gateway had until 0.6, by the
// mcp-gateway-admin command that replaces each. Until 0.8 they run
// mcp-gateway-admin, with a warning (D10).
var movedCommands = map[string]string{
	"inspect":      "inspect",
	"profile":      "profile",
	"review":       "review",
	"doctor":       "doctor",
	"admin-server": "serve",
}

// adminProgram is the program that has the administrators' commands.
const adminProgram = "mcp-gateway-admin"

// findAdmin returns mcp-gateway-admin: next to this program (as installed,
// and in bin/ of a checkout), else on PATH.
func findAdmin() (string, error) {
	if self, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(self), adminProgram)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return exec.LookPath(adminProgram)
}

// runMoved runs the moved command name as "mcp-gateway-admin NEW args".
// It returns only if that fails.
func runMoved(name string, args []string, stderr io.Writer) int {
	sub := movedCommands[name]
	_, _ = fmt.Fprintf(stderr, "mcp-gateway: \"mcp-gateway %s\" is deprecated and goes away in 0.8; use \"%s %s\"\n",
		name, adminProgram, sub)
	admin, err := findAdmin()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcp-gateway: %v\n", err)
		return 1
	}
	err = syscall.Exec(admin, append([]string{admin, sub}, args...), os.Environ())
	_, _ = fmt.Fprintf(stderr, "mcp-gateway: running %s: %v\n", admin, err)
	return 1
}

// usage prints the top-level help: how to run the gateway and its
// options (fs).
func usage(w io.Writer, fs *flag.FlagSet) {
	_, _ = fmt.Fprint(w, `usage: mcp-gateway [options]               run the gateway (as mcp-gateway.service does)
       mcp-gateway help                    this help

Related programs: mcp-gateway-admin (doctor, inspect, profile, review and
the server gateway-admin), mcp-connect (the stdio bridge agents start),
mcp-policy-bundle (signed policy bundles), mcp-gateway-notify (desktop
notifications).

Options of the gateway:
`)
	out := fs.Output()
	fs.SetOutput(w)
	fs.PrintDefaults()
	fs.SetOutput(out)
}

// runHelp is "mcp-gateway help [COMMAND]"; a moved command's help is
// mcp-gateway-admin's.
func runHelp(args []string, stdout, stderr io.Writer, fs *flag.FlagSet) int {
	if len(args) == 0 {
		usage(stdout, fs)
		return 0
	}
	if _, ok := movedCommands[args[0]]; ok {
		return runMoved(args[0], []string{"-h"}, stderr)
	}
	_, _ = fmt.Fprintf(stderr, "mcp-gateway: unknown command %q\n\n", args[0])
	usage(stderr, fs)
	return 2
}
