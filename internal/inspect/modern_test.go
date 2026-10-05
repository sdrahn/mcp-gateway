package inspect

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
)

// modernServer answers like a server of MCP 2026-07-28: server/discover,
// no initialize, every request with the protocol fields in _meta.
func modernServer(t *testing.T, conn net.Conn) {
	t.Helper()
	c := jsonrpc.NewConn(conn)
	for {
		m, err := c.Read()
		if err != nil {
			return
		}
		var p struct {
			Meta map[string]json.RawMessage `json:"_meta"`
		}
		_ = json.Unmarshal(m.Params, &p)
		if string(p.Meta["io.modelcontextprotocol/protocolVersion"]) != `"2026-07-28"` {
			_ = c.Write(jsonrpc.NewError(m.ID, -32602, "missing per-request metadata"))
			continue
		}
		var res string
		switch m.Method {
		case "server/discover":
			res = `{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},
				"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"modern","version":"2.0"}}}`
		case "tools/list":
			res = `{"resultType":"complete","tools":[{"name":"get_status"}],"ttlMs":60000,"cacheScope":"public"}`
		case "tools/call":
			res = `{"resultType":"complete","content":[{"type":"text","text":"fine"}]}`
		default:
			_ = c.Write(jsonrpc.NewError(m.ID, -32601, "no"))
			continue
		}
		var v any
		_ = json.Unmarshal([]byte(res), &v)
		r, _ := jsonrpc.NewResult(m.ID, v)
		_ = c.Write(r)
	}
}

func TestProbeModern(t *testing.T) {
	a, b := net.Pipe()
	go modernServer(t, b)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, res, err := Open(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if res.Server.Name != "modern" || res.ProtocolVersion != "2026-07-28" || len(res.Tools) != 1 {
		t.Fatalf("result %+v", res)
	}
	if r, err := s.Call("get_status", nil); err != nil || r.Text != "fine" {
		t.Fatalf("call: %+v %v", r, err)
	}
}

// pipeLauncher starts in-process servers: the first instance exits on
// server/discover, later ones are fakeServer.
type pipeLauncher struct {
	t       *testing.T
	mu      sync.Mutex
	started int
}

type pipeInstance struct{ net.Conn }

func (pipeInstance) Name() string { return "pipe" }

func (l *pipeLauncher) Start(context.Context, *config.Backend, principal.Principal, string) (supervisor.Instance, error) {
	a, b := net.Pipe()
	l.mu.Lock()
	l.started++
	first := l.started == 1
	l.mu.Unlock()
	if first {
		go func() {
			c := jsonrpc.NewConn(b)
			if m, err := c.Read(); err == nil && m.Method == "server/discover" {
				_ = b.Close()
			}
		}()
	} else {
		go fakeServer(l.t, b)
	}
	return pipeInstance{a}, nil
}

// A legacy server that exits on server/discover is started again and
// initialized.
func TestStartFragileServer(t *testing.T) {
	l := &pipeLauncher{t: t}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := Start(ctx, l, &config.Backend{Name: "fragile"}, principal.Discovery)
	if err != nil {
		t.Fatal(err)
	}
	if l.started != 2 || res.Server.Name != "fake" || !strings.HasPrefix(res.ProtocolVersion, "2025-") {
		t.Fatalf("started %d, result %+v", l.started, res)
	}
}
