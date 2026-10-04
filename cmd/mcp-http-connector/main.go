// Command mcp-http-connector connects an MCP server that speaks
// Streamable HTTP to mcp-gateway, which speaks stdio to its servers: each
// principal's instance of a server defined with url is this program,
// started by systemd in its own domain (mcpsrv_http_t), with its network
// limited to the server's addresses. It reads JSON-RPC messages from
// stdin, one per line, posts each to the server, and writes what the
// server sends (responses, its requests and notifications, on a POST's
// event stream or on the GET stream) to stdout. Headers may name
// credentials, ${CREDENTIAL:name}, read from $CREDENTIALS_DIRECTORY, so
// that secrets reach only this process. With -proxy, it tunnels through
// an HTTP proxy (CONNECT), and TLS still ends at the server.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sdrahn/mcp-gateway/internal/version"
)

const name = "mcp-http-connector"

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ", ") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	url := fs.String("url", "", "the MCP server's endpoint (https://…, or http:// to a local address)")
	var headers, resolve, proxyHeaders listFlag
	fs.Var(&headers, "header", `a request header, "Name: value"; ${CREDENTIAL:name} is replaced by the credential (repeatable)`)
	fs.Var(&resolve, "resolve", `connect to host:port at address, "host:port:address" (repeatable): the addresses the gateway resolved and the instance may reach`)
	proxy := fs.String("proxy", "", "tunnel to the server through this HTTP proxy (http://host:port or https://host:port; CONNECT, for an https:// -url); none is taken from the environment")
	fs.Var(&proxyHeaders, "proxy-header", `a header sent to the proxy with CONNECT, "Name: value", with ${CREDENTIAL:name} as in -header (repeatable)`)
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "usage: %s -url URL [options]\n\nConnects an MCP server that speaks Streamable HTTP to stdin/stdout.\n\n", name)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *showVersion {
		_, _ = fmt.Fprintln(stdout, name, version.Version)
		return 0
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	c, err := newConnector(*url, options{
		headers:      headers,
		resolve:      resolve,
		proxy:        *proxy,
		proxyHeaders: proxyHeaders,
		credDir:      os.Getenv("CREDENTIALS_DIRECTORY"),
	})
	if err != nil {
		log.Error("cannot start", "err", err)
		return 2
	}
	c.log = log
	if err := c.serve(ctx, stdin, stdout); err != nil {
		log.Error("connection to the server failed", "url", *url, "err", err)
		return 1
	}
	return 0
}
