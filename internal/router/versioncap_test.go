package router

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

// A client capped below the modern version (agents.max_version) is
// answered as by a gateway without it: server/discover is unknown, other
// modern requests name the versions it may use. Others are not affected.
func TestVersionCapModern(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	r.SetSettings(Settings{MaxVersion: map[string]string{"Kit": "2025-06-18", "new-agent": "2026-07-28"}})
	c := agent(t, r, alice(), "fs")
	kit := map[string]any{metaClientInfo: map[string]any{"name": "kit", "version": "0.121.1"}}

	m := c.roundTrip(1, "server/discover", withAgentMeta(nil, kit))
	if m.Error == nil || m.Error.Code != jsonrpc.CodeMethodNotFound {
		t.Fatalf("discover of a capped client: %+v", m)
	}
	m = c.roundTrip(2, "tools/list", withAgentMeta(nil, kit))
	if m.Error == nil || m.Error.Code != codeUnsupportedVersion || !strings.Contains(string(m.Error.Data), `"supported":["2025-06-18","2025-03-26","2024-11-05"]`) {
		t.Fatalf("request of a capped client: %+v", m.Error)
	}
	for i, name := range []string{"new-agent", "modern-agent"} {
		other := map[string]any{metaClientInfo: map[string]any{"name": name, "version": "1"}}
		if res := resultFields(t, c.roundTrip(10+i, "server/discover", withAgentMeta(nil, other))); string(res["supportedVersions"]) != `["2026-07-28"]` {
			t.Fatalf("discover of %s: %v", name, res)
		}
	}
}

// At initialize, a capped client gets its cap if it asks for a newer
// version, what it asks for otherwise.
func TestVersionCapInitialize(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	r.SetSettings(Settings{MaxVersion: map[string]string{"kit": "2025-06-18"}})
	for _, tc := range []struct{ client, asked, want string }{
		{"kit", "2025-11-25", "2025-06-18"},
		{"KIT", "2026-07-28", "2025-06-18"},
		{"kit", "2025-03-26", "2025-03-26"},
		{"other", "2025-11-25", "2025-11-25"},
	} {
		cTest, cGw := net.Pipe()
		cc := jsonrpc.NewConn(cTest)
		hello, _ := transport.NewHello("git")
		go r.ServeClient(context.Background(), jsonrpc.NewConn(cGw), alice(), hello)
		init, _ := jsonrpc.NewRequest(json.RawMessage(`1`), "initialize", map[string]any{"protocolVersion": tc.asked,
			"capabilities": map[string]any{}, "clientInfo": map[string]any{"name": tc.client, "version": "1"}})
		_ = cc.Write(init)
		m, err := cc.Read()
		if err != nil {
			t.Fatal(err)
		}
		_ = cc.Close()
		var res struct{ ProtocolVersion string }
		_ = json.Unmarshal(m.Result, &res)
		if res.ProtocolVersion != tc.want {
			t.Errorf("%s asking for %s: got %s, want %s", tc.client, tc.asked, res.ProtocolVersion, tc.want)
		}
	}
}
