package transport

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
)

func TestListenUnixPeerCred(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.sock")
	l, err := ListenUnix(path, 0o660, "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o660 {
		t.Errorf("mode = %v", fi.Mode().Perm())
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := net.Dial("unix", path)
		if err == nil {
			_ = c.Close()
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	<-done
	if c.Peer.UID != uint32(os.Getuid()) || c.Peer.PID == 0 {
		t.Errorf("peer = %+v", c.Peer)
	}
}

func TestListenUnixRefusesNonSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenUnix(path, 0o660, ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestHello(t *testing.T) {
	m, err := NewHello("fs")
	if err != nil {
		t.Fatal(err)
	}
	h, err := ParseHello(m)
	if err != nil || h.Server != "fs" {
		t.Fatalf("got %+v, %v", h, err)
	}
	if _, err := ParseHello(&jsonrpc.Message{JSONRPC: "2.0", ID: []byte("1"), Method: "initialize"}); err != ErrNoHello {
		t.Fatalf("want ErrNoHello, got %v", err)
	}
	bad := &jsonrpc.Message{JSONRPC: "2.0", Method: HelloMethod, Params: []byte(`{"version":9,"server":"fs"}`)}
	if _, err := ParseHello(bad); err == nil {
		t.Fatal("expected version error")
	}
}
