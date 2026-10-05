package router

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

// agentMetaFor is the _meta of a modern agent's request.
func agentMetaFor(extra map[string]any) map[string]any {
	m := map[string]any{
		metaProtocolVersion:    modernVersion,
		metaClientInfo:         map[string]any{"name": "modern-agent", "version": "1"},
		metaClientCapabilities: map[string]any{},
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// withAgentMeta returns params with the modern _meta.
func withAgentMeta(params map[string]any, extra map[string]any) map[string]any {
	out := map[string]any{"_meta": agentMetaFor(extra)}
	for k, v := range params {
		out[k] = v
	}
	return out
}

// agent connects like a modern agent on the unix socket: a hello naming
// server ("" for none: the aggregated endpoint), then requests with
// _meta, no initialize.
func agent(t *testing.T, r *Router, p principal.Principal, server string) *client {
	t.Helper()
	cTest, cGw := net.Pipe()
	c := &client{t: t, conn: jsonrpc.NewConn(cTest), msgs: make(chan *jsonrpc.Message, 32), done: make(chan struct{})}
	go func() {
		for {
			m, err := c.conn.Read()
			if err != nil {
				close(c.msgs)
				return
			}
			c.msgs <- m
		}
	}()
	var first *jsonrpc.Message
	if server != "" {
		first, _ = transport.NewHello(server)
	}
	gw := jsonrpc.NewConn(cGw)
	go func() {
		if first == nil {
			m, err := gw.Read()
			if err != nil {
				close(c.done)
				return
			}
			first = m
		}
		r.ServeClient(t.Context(), gw, p, first)
		close(c.done)
	}()
	t.Cleanup(c.close)
	return c
}

func resultFields(t *testing.T, m *jsonrpc.Message) map[string]json.RawMessage {
	t.Helper()
	if m.Error != nil {
		t.Fatalf("error %+v", m.Error)
	}
	var res map[string]json.RawMessage
	if err := json.Unmarshal(m.Result, &res); err != nil {
		t.Fatal(err)
	}
	return res
}

// A modern agent needs no initialize: server/discover tells what the
// endpoint offers, lists and calls work at once, with the fields MCP
// 2026-07-28 adds to results.
func TestAgent(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	c := agent(t, r, alice(), "fs")

	res := resultFields(t, c.roundTrip(1, "server/discover", withAgentMeta(nil, nil)))
	if string(res["supportedVersions"]) != `["2026-07-28"]` || string(res["resultType"]) != `"complete"` ||
		!strings.Contains(string(res["_meta"]), metaServerInfo) || strings.Contains(string(res["capabilities"]), "listChanged") {
		t.Fatalf("discover: %v", res)
	}

	m := c.roundTrip(2, "tools/list", withAgentMeta(nil, nil))
	res = resultFields(t, m)
	if got := names(t, m, "tools", "name"); strings.Join(got, ",") != "read_file,write_file,ask_roots" {
		t.Fatalf("tools %v", got)
	}
	if string(res["cacheScope"]) != `"private"` || string(res["ttlMs"]) != "60000" || string(res["resultType"]) != `"complete"` {
		t.Fatalf("list fields: %v", res)
	}

	m = c.roundTrip(3, "tools/call", withAgentMeta(map[string]any{"name": "read_file"}, nil))
	if text, isErr := toolText(t, m); isErr || text != "fs did read_file" {
		t.Fatalf("call: %q %v", text, isErr)
	}
	if !strings.Contains(string(m.Result), `"resultType":"complete"`) {
		t.Fatalf("call result %s", m.Result)
	}

	res = resultFields(t, c.roundTrip(4, "resources/read", withAgentMeta(map[string]any{"uri": "file:///ok/a.txt"}, nil)))
	if string(res["cacheScope"]) != `"private"` || string(res["ttlMs"]) != "0" {
		t.Fatalf("read fields: %v", res)
	}
}

// Errors follow MCP 2026-07-28: an unsupported version names the
// versions the gateway speaks, missing capabilities are invalid params,
// removed methods are unknown, and so is an unknown resource -32602.
func TestAgentErrors(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	c := agent(t, r, alice(), "fs")

	m := c.roundTrip(1, "tools/list", withAgentMeta(nil, map[string]any{metaProtocolVersion: "2027-03-01"}))
	if m.Error == nil || m.Error.Code != codeUnsupportedVersion || !strings.Contains(string(m.Error.Data), `"supported":["2026-07-28","2025-11-25"`) {
		t.Fatalf("version: %+v", m.Error)
	}
	m = c.roundTrip(2, "tools/list", map[string]any{"_meta": map[string]any{metaProtocolVersion: modernVersion}})
	if m.Error == nil || m.Error.Code != jsonrpc.CodeInvalidParams {
		t.Fatalf("no capabilities: %+v", m.Error)
	}
	for i, method := range []string{"initialize", "ping", "logging/setLevel", "resources/subscribe", "subscriptions/listen"} {
		if m := c.roundTrip(10+i, method, withAgentMeta(nil, nil)); m.Error == nil || m.Error.Code != jsonrpc.CodeMethodNotFound {
			t.Errorf("%s: %+v", method, m)
		}
	}
	m = c.roundTrip(3, "resources/read", withAgentMeta(map[string]any{"uri": "file:///ok/missing"}, nil))
	if m.Error == nil || m.Error.Code != jsonrpc.CodeInvalidParams {
		t.Fatalf("missing resource: %+v", m.Error)
	}
}

// The aggregated endpoint's lists are sorted by name.
func TestAgentAggregatedSorted(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	c := agent(t, r, alice(), "")
	got := names(t, c.roundTrip(1, "tools/list", withAgentMeta(nil, nil)), "tools", "name")
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Fatalf("not sorted: %v", got)
		}
	}
	if len(got) != 9 {
		t.Fatalf("tools %v", got)
	}
}

// A server with isolation: session gets one instance per principal for
// modern requests, which have no session.
func TestAgentIsolationSession(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	c := agent(t, r, alice(), "tmp")
	for i := 1; i <= 3; i++ {
		if text, _ := toolText(t, c.roundTrip(i, "tools/call", withAgentMeta(map[string]any{"name": "read_file"}, nil))); text != "tmp did read_file" {
			t.Fatalf("call %d: %q", i, text)
		}
	}
	if n := len(l.started("tmp")); n != 1 {
		t.Fatalf("%d instances", n)
	}
}

// A legacy server's request during a modern agent's call is refused: the
// gateway cannot ask a modern agent.
func TestAgentLegacyServerAsks(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	c := agent(t, r, alice(), "fs")
	text, _ := toolText(t, c.roundTrip(1, "tools/call", withAgentMeta(map[string]any{"name": "ask_roots"},
		map[string]any{metaClientCapabilities: map[string]any{"roots": map[string]any{}}})))
	if !strings.Contains(text, "roots error") || !strings.Contains(text, "2026-07-28") {
		t.Fatalf("got %q", text)
	}
}

// Log messages reach a modern request that asked for them, at its level,
// passed on to a modern server in its _meta.
func TestAgentLogLevel(t *testing.T) {
	r, _ := modernRouter(t)
	c := agent(t, r, alice(), "modern")
	if text, _ := toolText(t, c.roundTrip(1, "tools/call", withAgentMeta(map[string]any{"name": "read_log"}, nil))); text != "log level " {
		t.Fatalf("without a level: %q", text)
	}
	c.send(2, "tools/call", withAgentMeta(map[string]any{"name": "read_log"}, map[string]any{metaLogLevel: "info"}))
	if m := c.read(); m.Method != "notifications/message" {
		t.Fatalf("want the log message first, got %+v", m)
	}
	if text, _ := toolText(t, c.read()); text != `log level "info"` {
		t.Fatalf("with a level: %q", text)
	}
}

// notifications/cancelled cancels a modern request on the socket.
func TestAgentCancel(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	c := agent(t, r, alice(), "fs")
	c.send(7, "tools/call", withAgentMeta(map[string]any{"name": "slow"}, nil))
	time.Sleep(50 * time.Millisecond)
	n, _ := jsonrpc.NewNotification("notifications/cancelled", map[string]any{"requestId": 7})
	c.write(n)
	select {
	case <-l.started("fs")[0].cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("the backend was not told")
	}
	if text, _ := toolText(t, c.roundTrip(8, "tools/call", withAgentMeta(map[string]any{"name": "read_file"}, nil))); text != "fs did read_file" {
		t.Fatalf("after: %q", text)
	}
}

// recordConn collects what ServeRequest writes.
type recordConn struct {
	mu   sync.Mutex
	msgs []*jsonrpc.Message
}

func (c *recordConn) Read() (*jsonrpc.Message, error) { select {} }
func (c *recordConn) Close() error                    { return nil }
func (c *recordConn) Write(m *jsonrpc.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, m)
	return nil
}

// Over HTTP, the Mcp-Param headers of a tools/call must match its
// arguments, for tools whose schema marks parameters with x-mcp-header.
func TestAgentParamHeaders(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	r.Backends["regional"] = &config.Backend{Name: "regional", Isolation: config.IsolationPrincipal}
	call := func(region string, h http.Header) *jsonrpc.Message {
		t.Helper()
		m, _ := jsonrpc.NewRequest(json.RawMessage(`1`), "tools/call",
			withAgentMeta(map[string]any{"name": "read_region", "arguments": map[string]any{"region": region}}, nil))
		out := &recordConn{}
		r.ServeRequest(t.Context(), out, alice(), "regional", m, h)
		return out.msgs[len(out.msgs)-1]
	}
	if m := call("eu", http.Header{"Mcp-Param-Region": {"eu"}}); m.Error != nil {
		t.Fatalf("matching: %+v", m.Error)
	}
	for name, h := range map[string]http.Header{"missing": {}, "different": {"Mcp-Param-Region": {"us"}}} {
		if m := call("eu", h); m.Error == nil || m.Error.Code != codeHeaderMismatch {
			t.Errorf("%s: %+v", name, m)
		}
	}
	// Other transports have no headers to check.
	if m := call("eu", nil); m.Error != nil {
		t.Fatalf("no headers: %+v", m.Error)
	}
}

// recordPDP is fakePDP, keeping the inputs it decided on.
type recordPDP struct {
	fakePDP
	mu     sync.Mutex
	inputs []pep.Input
}

func (p *recordPDP) Decide(ctx context.Context, in pep.Input) (pep.Decision, error) {
	p.mu.Lock()
	p.inputs = append(p.inputs, in)
	p.mu.Unlock()
	return p.fakePDP.Decide(ctx, in)
}

// Policy sees a modern request's protocol version, capabilities and
// client, and no session.
func TestAgentPolicyInput(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	pdp := &recordPDP{}
	r.PDP = pdp
	c := agent(t, r, alice(), "fs")
	c.roundTrip(1, "tools/call", withAgentMeta(map[string]any{"name": "read_file"},
		map[string]any{metaClientCapabilities: map[string]any{"sampling": map[string]any{}}}))
	pdp.mu.Lock()
	defer pdp.mu.Unlock()
	var in *pep.Input
	for i := range pdp.inputs {
		if pdp.inputs[i].Action == "tools.call" {
			in = &pdp.inputs[i]
		}
	}
	if in == nil {
		t.Fatal("no decision")
	}
	if in.Context.ProtocolVersion != modernVersion || in.Principal.SessionID != "" || in.Principal.Client.Name != "modern-agent" ||
		in.Context.ClientCapabilities["sampling"] == nil {
		t.Fatalf("input %+v", in)
	}
}
