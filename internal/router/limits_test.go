package router

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

// idleConn is a client connection that reports itself idle, as an HTTP
// session without traffic does.
type idleConn struct {
	jsonrpc.MessageConn
	idle time.Duration
}

func (c idleConn) Idle() (time.Duration, bool) { return c.idle, true }

// openSession sends a hello for fs and an initialize over a connection
// that wrap may replace, and returns the client's end and the answer.
func openSession(t *testing.T, r *Router, p principal.Principal, wrap func(jsonrpc.MessageConn) jsonrpc.MessageConn) (*jsonrpc.Conn, *jsonrpc.Message) {
	t.Helper()
	return openSessionTo(t, r, "fs", p, wrap)
}

func openSessionTo(t *testing.T, r *Router, server string, p principal.Principal, wrap func(jsonrpc.MessageConn) jsonrpc.MessageConn) (*jsonrpc.Conn, *jsonrpc.Message) {
	t.Helper()
	cTest, cGw := net.Pipe()
	c := jsonrpc.NewConn(cTest)
	var gw jsonrpc.MessageConn = jsonrpc.NewConn(cGw)
	if wrap != nil {
		gw = wrap(gw)
	}
	hello, _ := transport.NewHello(server)
	go r.ServeClient(context.Background(), gw, p, hello)
	init, _ := jsonrpc.NewRequest(json.RawMessage(`1`), "initialize", map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test"},
	})
	if err := c.Write(init); err != nil {
		t.Fatal(err)
	}
	m, err := c.Read()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, m
}

func TestSessionLimit(t *testing.T) {
	r, _ := testRouter(t, 0)
	r.MaxSessionsPerPrincipal = 2
	for i := 0; i < 2; i++ {
		if _, m := openSession(t, r, alice(), nil); m.Error != nil {
			t.Fatalf("session %d: %+v", i, m.Error)
		}
	}
	// A third local session is refused: local connections are never idle.
	_, m := openSession(t, r, alice(), nil)
	if m.Error == nil || !strings.Contains(m.Error.Message, "session limit reached (2)") {
		t.Fatalf("third session: %+v", m)
	}
	// Other principals are not affected.
	if _, m := openSession(t, r, principal.Principal{Sub: "bob", Transport: principal.TransportUnix, SessionID: "b1"}, nil); m.Error != nil {
		t.Fatalf("bob: %+v", m.Error)
	}
}

func TestSessionLimitEndsIdleSession(t *testing.T) {
	r, _ := testRouter(t, 0)
	r.MaxSessionsPerPrincipal = 2
	wrap := func(d time.Duration) func(jsonrpc.MessageConn) jsonrpc.MessageConn {
		return func(c jsonrpc.MessageConn) jsonrpc.MessageConn { return idleConn{c, d} }
	}
	older, _ := openSession(t, r, alice(), wrap(10*time.Minute))
	if _, m := openSession(t, r, alice(), wrap(time.Minute)); m.Error != nil {
		t.Fatal(m.Error)
	}
	// At the limit, the longest-idle session makes room.
	if _, m := openSession(t, r, alice(), nil); m.Error != nil {
		t.Fatalf("new session at the limit: %+v", m.Error)
	}
	done := make(chan error, 1)
	go func() {
		_, err := older.Read()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("idle session still open")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("idle session not ended")
	}
}

func TestInstanceLimitPerPrincipal(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	r.MaxInstancesPerPrincipal = 1
	call := func(c *client, id int, server string) *jsonrpc.Message {
		return c.roundTrip(id, "tools/call", map[string]any{"name": "read_file"})
	}

	// fs runs, its session ends: the instance waits out its idle timeout.
	c1 := connect(t, r, alice(), "fs", nil)
	if text, _ := toolText(t, call(c1, 1, "fs")); text != "fs did read_file" {
		t.Fatalf("fs: %q", text)
	}
	c1.close()

	// git needs an instance: the idle fs instance makes room.
	c2 := connect(t, r, alice(), "git", nil)
	if text, _ := toolText(t, call(c2, 1, "git")); text != "git did read_file" {
		t.Fatalf("git: %q", text)
	}
	select {
	case <-l.started("fs")[0].closed:
	case <-time.After(2 * time.Second):
		t.Fatal("idle fs instance not stopped")
	}

	// With git in use, fs cannot start (a session for one server starts
	// it at initialize).
	_, m := openSessionTo(t, r, "fs", alice(), nil)
	if m.Error == nil || !strings.Contains(m.Error.Message, "instance limit reached (1)") {
		t.Fatalf("fs at the limit: %+v", m)
	}
	if n := len(l.started("fs")); n != 1 {
		t.Fatalf("fs started %d times", n)
	}

	// Another principal has its own limit.
	c4 := connect(t, r, principal.Principal{Sub: "bob", Transport: principal.TransportUnix, SessionID: "b1"}, "fs", nil)
	if text, _ := toolText(t, call(c4, 1, "fs")); text != "fs did read_file" {
		t.Fatalf("bob's fs: %q", text)
	}
}

func TestInstanceLimitTotal(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	r.MaxInstances = 1
	c1 := connect(t, r, alice(), "fs", nil)
	c1.roundTrip(1, "tools/call", map[string]any{"name": "read_file"})
	_, m := openSessionTo(t, r, "fs", principal.Principal{Sub: "bob", Transport: principal.TransportUnix, SessionID: "b1"}, nil)
	if m.Error == nil || !strings.Contains(m.Error.Message, "gateway instance limit reached (1)") {
		t.Fatalf("bob at the gateway limit: %+v", m)
	}
}

// A reload changes the limits for the sessions and instances that follow.
func TestSetSettingsLimits(t *testing.T) {
	r, _ := testRouter(t, 0)
	r.MaxSessionsPerPrincipal = 1
	if _, m := openSession(t, r, alice(), nil); m.Error != nil {
		t.Fatal(m.Error)
	}
	if _, m := openSession(t, r, alice(), nil); m.Error == nil {
		t.Fatal("second session admitted at a limit of 1")
	}
	r.SetSettings(Settings{MaxSessionsPerPrincipal: 2, MaxInstancesPerPrincipal: 1})
	if _, m := openSession(t, r, alice(), nil); m.Error != nil {
		t.Fatalf("second session at a limit of 2: %+v", m.Error)
	}
	if r.settings().MaxSessionsPerPrincipal != 2 {
		t.Fatal("settings not stored")
	}
	r.pool.mu.Lock()
	per := r.pool.maxPerPrincipal
	r.pool.mu.Unlock()
	if per != 1 {
		t.Fatalf("instance limit per principal %d", per)
	}
}
