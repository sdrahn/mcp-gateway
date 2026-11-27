package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/supervisor"
)

// startBridge serves argv on a local port; the server's exit status comes
// on the returned channel.
func startBridge(t *testing.T, argv ...string) (string, <-chan int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &bridge{token: "secret", argv: argv, stderr: io.Discard, done: make(chan int, 1)}
	out := make(chan int, 1)
	go func() { out <- b.serve(context.Background(), l, time.Minute) }()
	return l.Addr().String(), out
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

// The gateway's messages are the server's stdin, its stdout what the
// gateway reads; closing the connection ends the server and the bridge.
func TestBridgeRelays(t *testing.T) {
	addr, done := startBridge(t, "/bin/cat")
	if _, err := supervisor.DialBridge(ctx(t), addr, "wrong"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a wrong token: %v", err)
	}
	c, err := supervisor.DialBridge(ctx(t), addr, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := supervisor.DialBridge(ctx(t), addr, "secret"); err == nil || !strings.Contains(err.Error(), "409") {
		t.Errorf("a second connection: %v", err)
	}
	if _, err := io.WriteString(c, `{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != `{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n" {
		t.Fatalf("echo: %q %v", line, err)
	}
	_ = c.Close()
	select {
	case status := <-done:
		if status != 0 {
			t.Errorf("status %d", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the bridge did not exit after the gateway closed")
	}
}

// When the server ends, the gateway reads EOF, and the bridge exits with
// the server's status.
func TestBridgeServerEnds(t *testing.T) {
	addr, done := startBridge(t, "/bin/sh", "-c", "echo bye; exit 3")
	c, err := supervisor.DialBridge(ctx(t), addr, "secret")
	if err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(c)
	if err != nil || string(all) != "bye\n" {
		t.Errorf("read %q %v", all, err)
	}
	select {
	case status := <-done:
		if status != 3 {
			t.Errorf("status %d, want 3", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the bridge did not exit")
	}
}

// A server that does not start is reported to the gateway, not retried.
func TestBridgeServerMissing(t *testing.T) {
	addr, done := startBridge(t, "/nonexistent/server")
	if _, err := supervisor.DialBridge(ctx(t), addr, "secret"); err == nil || !strings.Contains(err.Error(), "502") {
		t.Errorf("a missing server: %v", err)
	}
	if status := <-done; status != 127 {
		t.Errorf("status %d", status)
	}
}

// DialBridge waits while the bridge does not listen yet (the pod is
// starting), until its context ends.
func TestDialBridgeWaits(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	c, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := supervisor.DialBridge(c, addr, "secret"); err == nil || time.Since(start) < 400*time.Millisecond {
		t.Errorf("no bridge: %v after %s", err, time.Since(start))
	}
}

func TestBridgeNoGateway(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &bridge{token: "secret", argv: []string{"/bin/cat"}, stderr: io.Discard, done: make(chan int, 1)}
	if status := b.serve(context.Background(), l, 100*time.Millisecond); status != 1 {
		t.Errorf("status %d", status)
	}
}
