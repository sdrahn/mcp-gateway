// Command mcp-oauth-helper makes the requests of a principal's sign-in to
// an MCP server defined with url for mcp-gateway, which makes no outbound
// connection itself (docs/architecture.md, section 5.7.3): it reads one
// request (a JSON object, internal/oauth.Request) from stdin, makes it
// to the one host it names, and writes the answer (oauth.Response) to
// stdout. systemd starts it for each step in its own domain
// (mcpsrv_oauth_t), with its network limited to that host's addresses
// (-resolve), or the proxy's.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/egress"
	"github.com/sdrahn/mcp-gateway/internal/landlock"
	"github.com/sdrahn/mcp-gateway/internal/oauth"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

const name = "mcp-oauth-helper"

// maxRequest bounds the request on stdin.
const maxRequest = 64 << 10

// timeout bounds a step.
const timeout = 30 * time.Second

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ", ") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// restrict is landlock.Self in the program, nil in tests that call run.
var restrict func(landlock.Rules) (landlock.Result, error)

func main() {
	restrict = landlock.Self
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var resolve, proxyHeaders listFlag
	fs.Var(&resolve, "resolve", `connect to host:port at address, "host:port:address" (repeatable)`)
	proxy := fs.String("proxy", "", "tunnel through this HTTP proxy (http://host:port or https://host:port); none is taken from the environment")
	fs.Var(&proxyHeaders, "proxy-header", `a header sent to the proxy with CONNECT, "Name: value"; ${CREDENTIAL:name} is replaced by the credential (repeatable)`)
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "usage: %s [options] <request.json\n\nMakes one sign-in request for mcp-gateway.\n\n", name)
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
	credDir := os.Getenv("CREDENTIALS_DIRECTORY")
	eo := egress.Options{Resolve: resolve}
	var err error
	if *proxy != "" {
		if eo.Proxy, err = egress.ParseProxy(*proxy); err == nil {
			eo.ProxyHeader, err = egress.ParseHeaders("-proxy-header", proxyHeaders, credDir)
		}
	}
	var transport *http.Transport
	if err == nil {
		transport, err = egress.Transport(eo)
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, name+":", err)
		return 2
	}
	if restrict != nil {
		// The kernel keeps the helper to its credentials and the ports
		// of the host or proxy (Landlock, D19). Before reading the
		// request: the program runs again restricted.
		if _, err := restrict(egress.Landlock(eo, nil, credDir)); err != nil {
			_, _ = fmt.Fprintln(stderr, name+":", err)
			return 2
		}
	}

	line, err := bufio.NewReader(io.LimitReader(stdin, maxRequest)).ReadBytes('\n')
	var resp oauth.Response
	var req oauth.Request
	switch {
	case err != nil && len(line) == 0:
		resp = oauth.Response{Error: oauth.HelperError, ErrorDescription: "no request: " + err.Error()}
	case json.Unmarshal(line, &req) != nil:
		resp = oauth.Response{Error: oauth.HelperError, ErrorDescription: "malformed request"}
	default:
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		client := &http.Client{Transport: transport, Timeout: timeout,
			// Redirects could lead to another host, which the unit may
			// not reach anyway; the endpoints are named exactly.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp = oauth.Do(ctx, client, req, credDir)
	}
	out, _ := json.Marshal(resp)
	if _, err := stdout.Write(append(out, '\n')); err != nil {
		_, _ = fmt.Fprintln(stderr, name+":", err)
		return 1
	}
	if resp.Error != "" {
		// For the journal: the error, never a token.
		_, _ = fmt.Fprintf(stderr, "%s: %s %s: %s\n", name, req.Op, req.URL, resp.Err())
	}
	return 0
}
