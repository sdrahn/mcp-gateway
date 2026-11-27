// Command mcp-stdio-bridge is the entrypoint of an instance's pod with
// the Kubernetes launcher (docs/architecture.md, section 5.12.3): it
// carries a stdio server's stdin and stdout to the gateway over one
// connection, so that the server needs no change, as on a host.
//
// It listens on -listen for one request, GET /stdio with the bearer
// token in -token-file and "Upgrade: mcp-stdio"; it then starts the
// server (the command after --), answers 101 Switching Protocols, and
// relays: what the gateway writes is the server's stdin, the server's
// stdout is what it reads. The server's stderr is the bridge's (the pod's
// log). When the gateway closes the connection, the server's stdin is
// closed, and it is killed if it has not ended within two seconds; when
// the server ends, the connection is closed. Either way the bridge exits
// with the server's status, and the pod ends. A request with another
// token, or a second one, is refused; without a request within -wait the
// bridge exits.
//
// The init container of the pod copies the bridge from the gateway's
// image, so it is a static binary (CGO_ENABLED=0).
package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/version"
)

const name = "mcp-stdio-bridge"

// Upgrade is the protocol the gateway asks for.
const Upgrade = "mcp-stdio"

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	listen := fs.String("listen", ":8765", "the address to listen on")
	tokenFile := fs.String("token-file", "", "the file with the token the gateway presents")
	wait := fs.Duration("wait", 5*time.Minute, "how long to wait for the gateway before exiting")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "usage: %s -token-file FILE [options] -- COMMAND [ARG...]\n\nCarries a stdio MCP server's stdin and stdout to the gateway.\n\n", name)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		_, _ = fmt.Fprintln(os.Stdout, name, version.Version)
		return 0
	}
	argv := fs.Args()
	if len(argv) == 0 || *tokenFile == "" {
		fs.Usage()
		return 2
	}
	raw, err := os.ReadFile(*tokenFile)
	token := strings.TrimSpace(string(raw))
	if err != nil || token == "" {
		_, _ = fmt.Fprintf(stderr, "%s: no token in %s: %v\n", name, *tokenFile, err)
		return 2
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	b := &bridge{token: token, argv: argv, stderr: stderr, done: make(chan int, 1)}
	return b.serve(ctx, l, *wait)
}

// bridge serves one gateway connection with one server process.
type bridge struct {
	token  string
	argv   []string
	stderr io.Writer

	mu     sync.Mutex
	taken  bool
	done   chan int // the server's exit status
	server *exec.Cmd
}

func (b *bridge) serve(ctx context.Context, l net.Listener, wait time.Duration) int {
	srv := &http.Server{Handler: b, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(l) }()
	defer func() { _ = srv.Close() }()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case status := <-b.done:
		return status
	case <-timer.C:
		b.mu.Lock()
		taken := b.taken
		b.mu.Unlock()
		if !taken {
			_, _ = fmt.Fprintf(b.stderr, "%s: no connection from the gateway within %s; exiting\n", name, wait)
			return 1
		}
		select {
		case status := <-b.done:
			return status
		case <-ctx.Done():
		}
	case <-ctx.Done():
	}
	// Stopped (the pod is deleted): end the server too.
	b.mu.Lock()
	if b.server != nil && b.server.Process != nil {
		_ = b.server.Process.Signal(syscall.SIGTERM)
	}
	b.mu.Unlock()
	select {
	case status := <-b.done:
		return status
	case <-time.After(3 * time.Second):
		return 1
	}
}

func (b *bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/stdio" || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	got, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if subtle.ConstantTimeCompare([]byte(got), []byte(b.token)) != 1 {
		http.Error(w, "not the gateway's token", http.StatusUnauthorized)
		return
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), Upgrade) {
		http.Error(w, "Upgrade: "+Upgrade+" expected", http.StatusUpgradeRequired)
		return
	}
	b.mu.Lock()
	if b.taken {
		b.mu.Unlock()
		http.Error(w, "the server is taken", http.StatusConflict)
		return
	}
	b.taken = true
	b.mu.Unlock()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "cannot upgrade", http.StatusInternalServerError)
		b.done <- 1
		return
	}
	cmd := exec.Command(b.argv[0], b.argv[1:]...)
	cmd.Stderr = b.stderr
	stdin, err1 := cmd.StdinPipe()
	stdout, err2 := cmd.StdoutPipe()
	if err := errors.Join(err1, err2); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		b.done <- 1
		return
	}
	if err := cmd.Start(); err != nil {
		_, _ = fmt.Fprintf(b.stderr, "%s: starting %s: %v\n", name, b.argv[0], err)
		http.Error(w, "the server did not start: "+err.Error(), http.StatusBadGateway)
		b.done <- 127
		return
	}
	b.mu.Lock()
	b.server = cmd
	b.mu.Unlock()
	conn, buf, err := hj.Hijack()
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		b.done <- 1
		return
	}
	_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + Upgrade + "\r\nConnection: Upgrade\r\n\r\n")
	_ = buf.Flush()
	b.relay(conn, buf.Reader, cmd, stdin, stdout)
}

// relay copies between the connection and the server until one side
// ends, then ends the other.
func (b *bridge) relay(conn net.Conn, in *bufio.Reader, cmd *exec.Cmd, stdin io.WriteCloser, stdout io.Reader) {
	exited := make(chan struct{})
	go func() {
		// The gateway's messages: stdin. When the gateway is gone, stdin
		// closes, which ends a well-behaved server.
		_, _ = io.Copy(stdin, in)
		_ = stdin.Close()
		select {
		case <-exited:
		case <-time.After(2 * time.Second):
			_ = cmd.Process.Kill()
		}
	}()
	// The server's messages: to the gateway, until stdout ends.
	_, _ = io.Copy(conn, stdout)
	err := cmd.Wait()
	close(exited)
	_ = conn.Close()
	status := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		status = ee.ExitCode()
		if status < 0 {
			status = 1
		}
	} else if err != nil {
		status = 1
	}
	b.done <- status
}
