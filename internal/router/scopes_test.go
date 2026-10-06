package router

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

// remoteAlice is alice over HTTP with a token of the scopes openid and mcp.
func remoteAlice() principal.Principal {
	return principal.Principal{Sub: "alice", Issuer: "https://idp", Transport: principal.TransportHTTP,
		Scopes: []string{"openid", "mcp"}, SessionID: "h" + time.Now().Format("150405.000000000")}
}

// memConn is a client connection in memory: what the router writes keeps
// the fields that are never sent (ScopeChallenge).
type memConn struct {
	in  chan *jsonrpc.Message
	out chan *jsonrpc.Message
}

func (c *memConn) Read() (*jsonrpc.Message, error) {
	m, ok := <-c.in
	if !ok {
		return nil, io.EOF
	}
	return m, nil
}
func (c *memConn) Write(m *jsonrpc.Message) error { c.out <- m; return nil }
func (c *memConn) Close() error                   { return nil }

// A call outside the token's scopes is a tool error naming the scopes
// that would allow it, and its response asks for the first of them
// (over HTTP, a 403 challenge); calls within are not marked.
func TestScopeDenial(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	check := func(t *testing.T, m *jsonrpc.Message) {
		t.Helper()
		text, isErr := toolText(t, m)
		if !isErr || text != "mcp-gateway: outside the token's scopes; a token with the scope mcp:write or mcp:admin would allow it" || m.ScopeChallenge != "mcp:write" {
			t.Fatalf("denial: %q %v %q", text, isErr, m.ScopeChallenge)
		}
	}

	t.Run("modern", func(t *testing.T) {
		call := func(name string) *jsonrpc.Message {
			m, _ := jsonrpc.NewRequest(json.RawMessage(`1`), "tools/call", withAgentMeta(map[string]any{"name": name}, nil))
			out := &recordConn{}
			r.ServeRequest(t.Context(), out, remoteAlice(), "fs", m, nil)
			return out.msgs[len(out.msgs)-1]
		}
		check(t, call("write_file"))
		if m := call("read_file"); m.ScopeChallenge != "" || strings.Contains(string(m.Result), "isError") {
			t.Fatalf("within: %+v", m)
		}
	})

	t.Run("session", func(t *testing.T) {
		c := &memConn{in: make(chan *jsonrpc.Message, 4), out: make(chan *jsonrpc.Message, 16)}
		hello, _ := transport.NewHello("fs")
		go r.ServeClient(t.Context(), c, remoteAlice(), hello)
		t.Cleanup(func() { close(c.in) })
		roundTrip := func(id int, method string, params any) *jsonrpc.Message {
			t.Helper()
			m, _ := jsonrpc.NewRequest(json.RawMessage(strings.Repeat("1", id)), method, params)
			c.in <- m
			for {
				select {
				case resp := <-c.out:
					if resp.IsResponse() && resp.Key() == m.Key() {
						return resp
					}
				case <-time.After(5 * time.Second):
					t.Fatalf("no response to %s", method)
				}
			}
		}
		roundTrip(1, "initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}})
		check(t, roundTrip(2, "tools/call", map[string]any{"name": "write_file"}))
		if m := roundTrip(3, "tools/call", map[string]any{"name": "read_file"}); m.ScopeChallenge != "" {
			t.Fatalf("within: %+v", m)
		}
	})
}
