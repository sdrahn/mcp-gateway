package router

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

// logBuffer collects a router's log for a test.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// captureLog makes r log to a buffer it returns; call it before any
// client connects.
func captureLog(r *Router) *logBuffer {
	l := &logBuffer{}
	r.Log = slog.New(slog.NewTextHandler(l, nil))
	return l
}

// waitLog waits for a line of l that contains all of parts.
func waitLog(t *testing.T, l *logBuffer, parts ...string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		for _, line := range strings.Split(l.String(), "\n") {
			ok := true
			for _, p := range parts {
				ok = ok && strings.Contains(line, p)
			}
			if ok {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no log line with %q in:\n%s", parts, l.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A client capped below the modern version (agents.max_version) is
// answered as by a gateway without it: server/discover is unknown, other
// modern requests name the versions it may use. Others are not affected.
func TestVersionCapModern(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	r.SetSettings(Settings{MaxVersion: map[string]string{"Kit": "2025-06-18", "new-agent": "2026-07-28"}})
	logs := captureLog(r)
	c := agent(t, r, alice(), "fs")
	kit := map[string]any{metaClientInfo: map[string]any{"name": "kit", "version": "0.121.1"}}

	m := c.roundTrip(1, "server/discover", withAgentMeta(nil, kit))
	if m.Error == nil || m.Error.Code != jsonrpc.CodeMethodNotFound {
		t.Fatalf("discover of a capped client: %+v", m)
	}
	// The log names the client and why it is refused.
	waitLog(t, logs, "agent discovery refused", "client=kit", "capped=2025-06-18")
	m = c.roundTrip(2, "tools/list", withAgentMeta(nil, kit))
	if m.Error == nil || m.Error.Code != codeUnsupportedVersion || !strings.Contains(string(m.Error.Data), `"supported":["2025-06-18","2025-03-26","2024-11-05"]`) {
		t.Fatalf("request of a capped client: %+v", m.Error)
	}
	for i, name := range []string{"new-agent", "modern-agent"} {
		other := map[string]any{metaClientInfo: map[string]any{"name": name, "version": "1"}}
		if res := resultFields(t, c.roundTrip(10+i, "server/discover", withAgentMeta(nil, other))); string(res["supportedVersions"]) != `["2026-07-28"]` {
			t.Fatalf("discover of %s: %v", name, res)
		}
		waitLog(t, logs, `msg="agent discovered"`, "client="+name, "client_version=1", "protocol=2026-07-28")
	}
}

// At initialize, a capped client gets its cap if it asks for a newer
// version, what it asks for otherwise.
func TestVersionCapInitialize(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	r.SetSettings(Settings{MaxVersion: map[string]string{"kit": "2025-06-18"}})
	logs := captureLog(r)
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
	// The log names the client, what it asked for, what it got, and the
	// cap that decided.
	waitLog(t, logs, `msg="session initialized"`, "client=KIT", "client_version=1", "requested=2026-07-28", "protocol=2025-06-18", "capped=2025-06-18")
	waitLog(t, logs, `msg="session initialized"`, "client=other", "requested=2025-11-25", "protocol=2025-11-25", `capped=""`)
}
