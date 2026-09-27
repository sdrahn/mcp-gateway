// Command mcp-connect is the stdio shim for local MCP clients that can only
// spawn a command. It connects to the gateway's unix socket and copies bytes
// between its stdin/stdout and the socket; authentication happens on the
// socket via kernel peer credentials.
//
// Usage in an MCP client configuration:
//
//	{ "command": "mcp-connect", "args": ["--server", "git"] }
//
// Skeleton: the byte copy and the server-selection handshake follow in the
// proof of concept (docs/architecture.md, sections 5.1 and 11).
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

func main() {
	socket := flag.String("socket", config.DefaultSocket, "gateway unix socket")
	server := flag.String("server", "all", `backend to connect to, or "all" for the aggregated endpoint`)
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("mcp-connect", version.Version)
		return
	}
	fmt.Fprintf(os.Stderr, "mcp-connect: not implemented yet (socket %s, server %s)\n", *socket, *server)
	os.Exit(1)
}
