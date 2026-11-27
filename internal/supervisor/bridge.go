package supervisor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// BridgeUpgrade is the protocol mcp-stdio-bridge speaks after the
// gateway's request (cmd/mcp-stdio-bridge).
const BridgeUpgrade = "mcp-stdio"

// bridgeConn is an instance's stdio across the pod boundary: what is
// written is the server's stdin, what is read its stdout.
type bridgeConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bridgeConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// DialBridge connects to the mcp-stdio-bridge at addr (host:port) with
// token and returns the server's stdio. It retries while the bridge is
// not listening yet, until ctx ends.
func DialBridge(ctx context.Context, addr, token string) (io.ReadWriteCloser, error) {
	var last error
	for {
		c, err := dialBridgeOnce(ctx, addr, token)
		if err == nil {
			return c, nil
		}
		last = err
		if _, refused := err.(*refusedError); refused {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("mcp-stdio-bridge at %s: %w (last: %v)", addr, ctx.Err(), last)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// refusedError is an answer of the bridge's: retrying does not help.
type refusedError struct{ status, body string }

func (e *refusedError) Error() string {
	return fmt.Sprintf("mcp-stdio-bridge refused the connection: %s %s", e.status, strings.TrimSpace(e.body))
}

func dialBridgeOnce(ctx context.Context, addr, token string) (*bridgeConn, error) {
	d := net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	req := "GET /stdio HTTP/1.1\r\nHost: " + addr + "\r\nAuthorization: Bearer " + token +
		"\r\nConnection: Upgrade\r\nUpgrade: " + BridgeUpgrade + "\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		_ = conn.Close()
		return nil, err
	}
	r := bufio.NewReader(conn)
	resp, err := http.ReadResponse(r, &http.Request{Method: http.MethodGet})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = conn.Close()
		return nil, &refusedError{resp.Status, string(body)}
	}
	_ = conn.SetDeadline(time.Time{})
	return &bridgeConn{Conn: conn, r: r}, nil
}
