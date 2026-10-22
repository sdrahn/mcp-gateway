package router

import (
	"context"
	"encoding/json"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

// zed is a remote principal without a local account: no uid, no home.
func zed() principal.Principal {
	return principal.Principal{Sub: "zed", Issuer: "https://idp.example", Transport: principal.TransportHTTP, SessionID: "zed1"}
}

// A server whose definition names ${HOME} is not offered to a principal
// without a home: it is left out of the tool list (from the shared
// discovery instance as from an instance of its own), and a call is
// refused without starting an instance, whose root would be "/".
// Principals with a home use it as before.
func TestNoHomeServerLeftOut(t *testing.T) {
	r, l := sharedRouter(t)
	r.Backends["fs"].Command = []string{"/usr/libexec/mcp-servers/mcp-server-fs", "--root", "${HOME}"}
	r.Backends["git"].Command = []string{"/usr/bin/git-mcp", "--repos", "${HOME}/src"}

	c := connect(t, r, zed(), "", nil)
	got := names(t, c.roundTrip(1, "tools/list", map[string]any{}), "tools", "name")
	if slices.ContainsFunc(got, func(n string) bool { return strings.HasPrefix(n, "fs__") || strings.HasPrefix(n, "git__") }) ||
		!slices.Contains(got, "tmp__read_file") {
		t.Errorf("tools %v", got)
	}
	m := c.roundTrip(2, "tools/call", map[string]any{"name": "fs__read_file", "arguments": map[string]any{"path": "/etc/passwd"}})
	if m.Error == nil || !strings.Contains(m.Error.Message, "server fs works in the user's home directory; a principal without a local account has none") {
		t.Errorf("call: %+v", m)
	}
	for _, fi := range append(l.started("fs"), l.started("git")...) {
		if fi.p.Sub == "zed" {
			t.Errorf("an instance started for zed: %+v", fi.p)
		}
	}

	a := connect(t, r, alice(), "", nil)
	got = names(t, a.roundTrip(1, "tools/list", map[string]any{}), "tools", "name")
	if !slices.Contains(got, "fs__read_file") || !slices.Contains(got, "git__read_file") {
		t.Errorf("alice's tools %v", got)
	}
	if text, isErr := toolText(t, a.roundTrip(2, "tools/call", map[string]any{"name": "fs__read_file", "arguments": map[string]any{}})); isErr {
		t.Errorf("alice's call: %s", text)
	}
}

// At a server's own endpoint, the session cannot open.
func TestNoHomeServerEndpoint(t *testing.T) {
	r, _ := testRouter(t, 0)
	r.Backends["fs"].Command = []string{"/usr/libexec/mcp-servers/mcp-server-fs", "--root", "${HOME}"}
	cTest, cGw := net.Pipe()
	conn := jsonrpc.NewConn(cTest)
	t.Cleanup(func() { _ = conn.Close() })
	hello, _ := transport.NewHello("fs")
	go r.ServeClient(context.Background(), jsonrpc.NewConn(cGw), zed(), hello)
	init, _ := jsonrpc.NewRequest(json.RawMessage(`0`), "initialize", map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test"},
	})
	if err := conn.Write(init); err != nil {
		t.Fatal(err)
	}
	m, err := conn.Read()
	if err != nil || m.Error == nil || !strings.Contains(m.Error.Message, "works in the user's home directory") {
		t.Errorf("initialize: %+v (%v)", m, err)
	}
}
