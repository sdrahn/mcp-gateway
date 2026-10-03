package main

import (
	"flag"
	"fmt"
	"io"
)

// command is a subcommand of mcp-gateway: "mcp-gateway NAME [options]".
type command struct {
	name    string
	summary string
	run     func(args []string, stdout, stderr io.Writer) int
}

// commands are the subcommands, in the order the usage lists them. Each
// prints its own options with -h.
var commands = []command{
	{"inspect", "start an MCP server, list its tools, draft a definition and roles, check role data", runInspect},
	{"profile", "run a registered server in a permissive SELinux domain and draft its policy module", runProfile},
	{"review", "scan an MCP server's source for what it does to the system", runReview},
	{"doctor", "check the installation: services, policy, servers, SELinux, polkit, principals", runDoctor},
	{"admin-server", "the MCP server gateway-admin: the doctor, configuration and decisions for agents", runAdminServer},
}

func findCommand(name string) *command {
	for i := range commands {
		if commands[i].name == name {
			return &commands[i]
		}
	}
	return nil
}

// usage prints the top-level help: how to run the gateway, the
// subcommands, and the gateway's options (fs).
func usage(w io.Writer, fs *flag.FlagSet) {
	_, _ = fmt.Fprint(w, `usage: mcp-gateway [options]               run the gateway (as mcp-gateway.service does)
       mcp-gateway COMMAND [options]       run a command
       mcp-gateway help [COMMAND]          this help, or a command's

Commands:
`)
	for _, c := range commands {
		_, _ = fmt.Fprintf(w, "  %-13s %s\n", c.name, c.summary)
	}
	_, _ = fmt.Fprint(w, `
"mcp-gateway COMMAND -h" shows a command's options. Related programs:
mcp-connect (the stdio bridge agents start), mcp-policy-bundle (signed
policy bundles), mcp-gateway-notify (desktop notifications).

Options of the gateway:
`)
	out := fs.Output()
	fs.SetOutput(w)
	fs.PrintDefaults()
	fs.SetOutput(out)
}

// runHelp is "mcp-gateway help [COMMAND]".
func runHelp(args []string, stdout, stderr io.Writer, fs *flag.FlagSet) int {
	if len(args) == 0 {
		usage(stdout, fs)
		return 0
	}
	c := findCommand(args[0])
	if c == nil {
		_, _ = fmt.Fprintf(stderr, "mcp-gateway: unknown command %q\n\n", args[0])
		usage(stderr, fs)
		return 2
	}
	return c.run([]string{"-h"}, stdout, stderr)
}
