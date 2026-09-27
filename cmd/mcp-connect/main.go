// Command mcp-connect is the stdio shim for local MCP clients that can only
// spawn a command. It connects to the gateway's unix socket, selects a
// backend with a hello notification, and then copies bytes between its
// stdin/stdout and the socket. Authentication happens on the socket via
// kernel peer credentials; the shim holds no secrets.
//
// Usage in an MCP client configuration:
//
//	{ "command": "mcp-connect", "args": ["--server", "fs"] }
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/transport"
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
	if err := run(*socket, *server, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mcp-connect:", err)
		os.Exit(1)
	}
}

func run(socket, server string, stdin io.Reader, stdout io.Writer) error {
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	if server != "all" {
		hello, err := transport.NewHello(server)
		if err != nil {
			return err
		}
		b, err := json.Marshal(hello)
		if err != nil {
			return err
		}
		if _, err := c.Write(append(b, '\n')); err != nil {
			return err
		}
	}

	// stdin → socket; on EOF half-close so the gateway sees the end of
	// input while responses can still arrive.
	go func() {
		_, _ = io.Copy(c, stdin)
		_ = c.CloseWrite()
	}()
	// socket → stdout; the session is over when the gateway closes.
	_, err = io.Copy(stdout, c)
	return err
}
