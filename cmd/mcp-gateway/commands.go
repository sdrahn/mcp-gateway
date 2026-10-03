package main

import (
	"flag"
	"fmt"
	"io"
)

// movedCommands are the subcommands mcp-gateway had until 0.6, by the
// mcp-gateway-admin command that replaced each in 0.7. Since 0.8 they are
// unknown commands; the error names the replacement.
var movedCommands = map[string]string{
	"inspect":      "inspect",
	"profile":      "profile",
	"review":       "review",
	"doctor":       "doctor",
	"admin-server": "serve",
}

// unknownCommand reports that name is not a command (status 2).
func unknownCommand(name string, w io.Writer, fs *flag.FlagSet) int {
	if sub, ok := movedCommands[name]; ok {
		_, _ = fmt.Fprintf(w, "mcp-gateway: unknown command %q: it is \"mcp-gateway-admin %s\" since 0.7\n", name, sub)
		return 2
	}
	_, _ = fmt.Fprintf(w, "mcp-gateway: unknown command %q\n\n", name)
	usage(w, fs)
	return 2
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

// runHelp is "mcp-gateway help"; any command named is unknown.
func runHelp(args []string, stdout, stderr io.Writer, fs *flag.FlagSet) int {
	if len(args) == 0 {
		usage(stdout, fs)
		return 0
	}
	return unknownCommand(args[0], stderr, fs)
}
