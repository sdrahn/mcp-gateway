// mcp-gateway-admin has the commands for administrators of the MCP
// gateway: doctor, the server gateway-admin (serve), and the onboarding
// commands inspect, profile and review, which run mcp-gateway-tools
// (package mcp-gateway-tools).
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/sdrahn/mcp-gateway/internal/version"
)

// command is a command of mcp-gateway-admin: "mcp-gateway-admin NAME [options]".
type command struct {
	name    string
	summary string
	run     func(args []string, stdout, stderr io.Writer) int
}

// commands are the commands, in the order the usage lists them. Each
// prints its own options with -h.
var commands = []command{
	{"doctor", "check the installation: services, policy, servers, SELinux, polkit, principals", runDoctor},
	{"inspect", "start an MCP server, list its tools, draft a definition and roles, check role data", tool("inspect")},
	{"profile", "run a registered server in a permissive SELinux domain and draft its policy module", tool("profile")},
	{"review", "scan an MCP server's source for what it does to the system", tool("review")},
	{"serve", "the MCP server gateway-admin: the doctor, configuration and decisions for agents", runServe},
}

func findCommand(name string) *command {
	for i := range commands {
		if commands[i].name == name {
			return &commands[i]
		}
	}
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		return runHelp(args[1:], stdout, stderr)
	case "version", "-version", "--version":
		say(stdout, "mcp-gateway-admin", version.Version)
		return 0
	}
	c := findCommand(args[0])
	if c == nil {
		sayf(stderr, "mcp-gateway-admin: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
	return c.run(args[1:], stdout, stderr)
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `usage: mcp-gateway-admin COMMAND [options]   run a command
       mcp-gateway-admin help [COMMAND]        this help, or a command's
       mcp-gateway-admin --version

Commands:
`)
	for _, c := range commands {
		_, _ = fmt.Fprintf(w, "  %-9s %s\n", c.name, c.summary)
	}
	_, _ = fmt.Fprint(w, `
"mcp-gateway-admin COMMAND -h" shows a command's options. inspect,
profile and review are in the package mcp-gateway-tools.
`)
}

// runHelp is "mcp-gateway-admin help [COMMAND]".
func runHelp(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stdout)
		return 0
	}
	c := findCommand(args[0])
	if c == nil {
		sayf(stderr, "mcp-gateway-admin: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
	return c.run([]string{"-h"}, stdout, stderr)
}

// say and sayf write a line of output; a failed write to the terminal
// leaves nothing to report it on.
func say(w io.Writer, a ...any) { _, _ = fmt.Fprintln(w, a...) }

func sayf(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format+"\n", a...) }
