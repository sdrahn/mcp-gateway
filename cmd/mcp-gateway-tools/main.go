// mcp-gateway-tools has the commands that onboard MCP servers: inspect,
// profile and review. Administrators run them as "mcp-gateway-admin
// COMMAND"; it is a program of its own so that the package
// mcp-gateway-tools can bring what they need (the SELinux policy
// development files) without the gateway needing it.
package main

import (
	"io"
	"os"

	"github.com/sdrahn/mcp-gateway/internal/version"
)

var commands = map[string]func(args []string, stdout, stderr io.Writer) int{
	"inspect": runInspect,
	"profile": runProfile,
	"review":  runReview,
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		say(stderr, usage)
		return 2
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		say(stdout, usage)
		return 0
	case "--version":
		say(stdout, "mcp-gateway-tools", version.Version)
		return 0
	}
	c := commands[args[0]]
	if c == nil {
		sayf(stderr, "mcp-gateway-tools: unknown command %q\n%s", args[0], usage)
		return 2
	}
	return c(args[1:], stdout, stderr)
}

const usage = `usage: mcp-gateway-admin inspect|profile|review [options]

This is mcp-gateway-tools, which mcp-gateway-admin runs for these
commands; "mcp-gateway-admin help" describes them.`
