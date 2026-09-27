package router

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

func testRouter(t *testing.T, idle time.Duration) (*Router, *fakeLauncher) {
	t.Helper()
	l := newFakeLauncher(t)
	r := &Router{
		Backends: map[string]*config.Backend{
			"fs":  {Name: "fs", Isolation: config.IsolationPrincipal},
			"git": {Name: "git", Isolation: config.IsolationPrincipal},
			"tmp": {Name: "tmp", Isolation: config.IsolationSession},
		},
		Launcher:    l,
		PDP:         fakePDP{},
		Broker:      mustBroker(t, broker.Options{Timeout: time.Second}),
		IdleTimeout: idle,
	}
	t.Cleanup(func() { r.init(); r.pool.closeAll() })
	return r, l
}

func mustBroker(t *testing.T, o broker.Options) *broker.Broker {
	t.Helper()
	b, err := broker.New(o)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var sessionCounter int

func alice() principal.Principal {
	sessionCounter++
	uid := uint32(1001)
	return principal.Principal{Sub: "alice", UID: &uid, Transport: principal.TransportUnix,
		SessionID: "s" + string(rune('a'+sessionCounter%26)) + time.Now().Format("150405.000000000")}
}

type client struct {
	t    *testing.T
	conn *jsonrpc.Conn
	msgs chan *jsonrpc.Message
	done chan struct{}
}

// connect starts a session. server "" means no hello (aggregated).
func connect(t *testing.T, r *Router, p principal.Principal, server string, caps map[string]any) *client {
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
	gwConn := jsonrpc.NewConn(cGw)
	var first *jsonrpc.Message
	init, _ := jsonrpc.NewRequest(json.RawMessage(`0`), "initialize", map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": caps, "clientInfo": map[string]any{"name": "test"},
	})
	if server == "" {
		first = init
	} else {
		first, _ = transport.NewHello(server)
	}
	go func() {
		r.ServeClient(context.Background(), gwConn, p, first)
		close(c.done)
	}()
	if server != "" {
		c.write(init)
	}
	if m := c.read(); m.Key() != "0" || m.Error != nil {
		t.Fatalf("initialize: %+v", m)
	}
	t.Cleanup(c.close)
	return c
}

func (c *client) close() {
	_ = c.conn.Close()
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
		c.t.Error("session did not end")
	}
}

func (c *client) write(m *jsonrpc.Message) {
	c.t.Helper()
	if err := c.conn.Write(m); err != nil {
		c.t.Fatal(err)
	}
}

func (c *client) send(id int, method string, params any) {
	c.t.Helper()
	m, err := jsonrpc.NewRequest(json.RawMessage(itoa(id)), method, params)
	if err != nil {
		c.t.Fatal(err)
	}
	c.write(m)
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func (c *client) read() *jsonrpc.Message {
	c.t.Helper()
	select {
	case m, ok := <-c.msgs:
		if !ok {
			c.t.Fatal("connection closed")
		}
		return m
	case <-time.After(3 * time.Second):
		c.t.Fatal("timeout waiting for gateway message")
	}
	return nil
}

func (c *client) roundTrip(id int, method string, params any) *jsonrpc.Message {
	c.t.Helper()
	c.send(id, method, params)
	m := c.read()
	if m.Key() != itoa(id) {
		c.t.Fatalf("want response %d, got %+v", id, m)
	}
	return m
}

func toolText(t *testing.T, m *jsonrpc.Message) (string, bool) {
	t.Helper()
	var r struct {
		Content []struct{ Text string }
		IsError bool
	}
	if err := json.Unmarshal(m.Result, &r); err != nil || len(r.Content) == 0 {
		t.Fatalf("not a tool result: %+v (%v)", m, err)
	}
	return r.Content[0].Text, r.IsError
}

func names(t *testing.T, m *jsonrpc.Message, field, key string) []string {
	t.Helper()
	var res map[string][]map[string]any
	if err := json.Unmarshal(m.Result, &res); err != nil {
		t.Fatalf("%s: %v (%+v)", field, err, m)
	}
	var out []string
	for _, it := range res[field] {
		out = append(out, it[key].(string))
	}
	return out
}

func TestSingleEndpoint(t *testing.T) {
	r, _ := testRouter(t, 0)
	c := connect(t, r, alice(), "fs", nil)

	got := names(t, c.roundTrip(1, "tools/list", map[string]any{}), "tools", "name")
	if strings.Join(got, ",") != "read_file,write_file,ask_roots" {
		t.Fatalf("tools = %v (both pages, delete_file filtered)", got)
	}
	if text, isErr := toolText(t, c.roundTrip(2, "tools/call", map[string]any{"name": "read_file"})); isErr || text != "fs did read_file" {
		t.Fatalf("got %q %v", text, isErr)
	}
	text, isErr := toolText(t, c.roundTrip(3, "tools/call", map[string]any{"name": "delete_file"}))
	if !isErr || !strings.Contains(text, "not yours") {
		t.Fatalf("got %q %v", text, isErr)
	}
	if m := c.roundTrip(4, "tools/secret", map[string]any{}); m.Error == nil || m.Error.Code != jsonrpc.CodeMethodNotFound {
		t.Fatalf("got %+v", m)
	}
	if m := c.roundTrip(5, "ping", nil); m.Error != nil {
		t.Fatalf("ping: %+v", m)
	}
}

func TestSingleEndpointInitializeMirrorsBackend(t *testing.T) {
	r, _ := testRouter(t, 0)
	cTest, cGw := net.Pipe()
	cc := jsonrpc.NewConn(cTest)
	hello, _ := transport.NewHello("git")
	go r.ServeClient(context.Background(), jsonrpc.NewConn(cGw), alice(), hello)
	defer func() { _ = cc.Close() }()
	init, _ := jsonrpc.NewRequest(json.RawMessage(`1`), "initialize", map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}})
	_ = cc.Write(init)
	m, err := cc.Read()
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		ProtocolVersion string
		ServerInfo      struct{ Name string }
	}
	_ = json.Unmarshal(m.Result, &res)
	if res.ProtocolVersion != "2025-03-26" || res.ServerInfo.Name != "fake-git" {
		t.Fatalf("initialize result %s", m.Result)
	}
}

func TestAggregatedTools(t *testing.T) {
	r, _ := testRouter(t, 0)
	c := connect(t, r, alice(), "", nil)

	got := names(t, c.roundTrip(1, "tools/list", map[string]any{}), "tools", "name")
	want := "fs__read_file,fs__write_file,fs__ask_roots,git__read_file,git__write_file,git__ask_roots,tmp__read_file,tmp__write_file,tmp__ask_roots"
	if strings.Join(got, ",") != want {
		t.Fatalf("tools = %v", got)
	}
	if text, _ := toolText(t, c.roundTrip(2, "tools/call", map[string]any{"name": "git__read_file"})); text != "git did read_file" {
		t.Fatalf("routed to %q", text)
	}
	for i, bad := range []string{"read_file", "nope__read_file", "git__"} {
		if m := c.roundTrip(10+i, "tools/call", map[string]any{"name": bad}); m.Error == nil || m.Error.Code != jsonrpc.CodeInvalidParams {
			t.Errorf("%q: %+v", bad, m)
		}
	}
}

func TestAggregatedResourcesAndPrompts(t *testing.T) {
	r, _ := testRouter(t, 0)
	c := connect(t, r, alice(), "", nil)

	uris := names(t, c.roundTrip(1, "resources/list", map[string]any{}), "resources", "uri")
	if strings.Join(uris, ",") != "mcp+fs:file:///ok/a.txt,mcp+git:file:///ok/a.txt,mcp+tmp:file:///ok/a.txt" {
		t.Fatalf("resources = %v", uris)
	}
	tmpls := names(t, c.roundTrip(2, "resources/templates/list", map[string]any{}), "resourceTemplates", "uriTemplate")
	if len(tmpls) != 3 || tmpls[0] != "mcp+fs:file:///ok/{name}" {
		t.Fatalf("templates = %v", tmpls)
	}

	m := c.roundTrip(3, "resources/read", map[string]any{"uri": "mcp+git:file:///ok/a.txt"})
	if !strings.Contains(string(m.Result), `"uri":"mcp+git:file:///ok/a.txt"`) || !strings.Contains(string(m.Result), "git content") {
		t.Fatalf("read: %s", m.Result)
	}
	if m := c.roundTrip(4, "resources/read", map[string]any{"uri": "mcp+fs:file:///secret"}); m.Error == nil || m.Error.Code != jsonrpc.CodeForbidden {
		t.Fatalf("secret: %+v", m)
	}
	if m := c.roundTrip(5, "resources/read", map[string]any{"uri": "file:///ok/a.txt"}); m.Error == nil || m.Error.Code != jsonrpc.CodeInvalidParams {
		t.Fatalf("unnamespaced: %+v", m)
	}

	prompts := names(t, c.roundTrip(6, "prompts/list", map[string]any{}), "prompts", "name")
	if strings.Join(prompts, ",") != "fs__summarize,git__summarize,tmp__summarize" {
		t.Fatalf("prompts = %v", prompts)
	}
	if m := c.roundTrip(7, "prompts/get", map[string]any{"name": "git__summarize"}); !strings.Contains(string(m.Result), "git prompt summarize") {
		t.Fatalf("prompts/get: %s", m.Result)
	}
	m = c.roundTrip(8, "completion/complete", map[string]any{"ref": map[string]any{"type": "ref/resource", "uri": "mcp+fs:file:///ok/{name}"}, "argument": map[string]any{"name": "name", "value": "a"}})
	if !strings.Contains(string(m.Result), `"fs"`) {
		t.Fatalf("completion: %+v", m)
	}
}

func TestAskApproval(t *testing.T) {
	r, _ := testRouter(t, 0)
	c := connect(t, r, alice(), "fs", map[string]any{"elicitation": map[string]any{}})

	c.send(1, "tools/call", map[string]any{"name": "write_file"})
	el := c.read()
	if el.Method != "elicitation/create" || !strings.HasPrefix(el.Key(), `"mcpgw-`) {
		t.Fatalf("want elicitation, got %+v", el)
	}
	c.write(result(t, el.ID, map[string]any{"action": "accept", "content": map[string]any{"scope": "session"}}))
	if text, isErr := toolText(t, c.read()); isErr || text != "fs did write_file" {
		t.Fatalf("got %q %v", text, isErr)
	}
	// The session grant applies; no new elicitation.
	if text, _ := toolText(t, c.roundTrip(2, "tools/call", map[string]any{"name": "write_file"})); text != "fs did write_file" {
		t.Fatalf("got %q", text)
	}
}

func TestAskWithoutElicitationSupport(t *testing.T) {
	r, _ := testRouter(t, 0)
	c := connect(t, r, alice(), "fs", nil)
	text, isErr := toolText(t, c.roundTrip(1, "tools/call", map[string]any{"name": "write_file"}))
	if !isErr || !strings.Contains(text, "approval via form required") {
		t.Fatalf("got %q %v", text, isErr)
	}
}

func TestInstanceSharedPerPrincipal(t *testing.T) {
	r, l := testRouter(t, 50*time.Millisecond)
	p1, p2 := alice(), alice()
	c1 := connect(t, r, p1, "fs", nil)
	c2 := connect(t, r, p2, "fs", nil)
	c1.roundTrip(1, "tools/call", map[string]any{"name": "read_file"})
	c2.roundTrip(1, "tools/call", map[string]any{"name": "read_file"})
	if n := len(l.started("fs")); n != 1 {
		t.Fatalf("fs started %d times, want 1 shared instance", n)
	}

	// Another principal gets its own instance.
	bob := principal.Principal{Sub: "bob", Transport: principal.TransportUnix, SessionID: "bob1"}
	c3 := connect(t, r, bob, "fs", nil)
	c3.roundTrip(1, "tools/call", map[string]any{"name": "read_file"})
	if n := len(l.started("fs")); n != 2 {
		t.Fatalf("fs started %d times, want 2", n)
	}

	// The shared instance survives one session ending, and stops after the
	// idle timeout once both have ended.
	inst := l.started("fs")[0]
	c1.close()
	c2.roundTrip(2, "tools/call", map[string]any{"name": "read_file"})
	c2.close()
	select {
	case <-inst.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("idle instance not stopped")
	}
}

func TestInstancePerSession(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	p := alice()
	c1 := connect(t, r, p, "tmp", nil)
	p.SessionID += "-2"
	c2 := connect(t, r, p, "tmp", nil)
	_, _ = c1, c2
	insts := l.started("tmp")
	if len(insts) != 2 {
		t.Fatalf("tmp started %d times, want 2", len(insts))
	}
	c1.close()
	select {
	case <-insts[0].closed:
	case <-time.After(2 * time.Second):
		t.Fatal("session instance not stopped with its session")
	}
}

func TestBackendRequestDuringCall(t *testing.T) {
	r, _ := testRouter(t, 0)
	c := connect(t, r, alice(), "fs", map[string]any{"roots": map[string]any{}})
	c.send(1, "tools/call", map[string]any{"name": "ask_roots"})
	req := c.read()
	if req.Method != "roots/list" || !strings.HasPrefix(req.Key(), `"mcpgw-`) {
		t.Fatalf("want relayed roots/list, got %+v", req)
	}
	c.write(result(t, req.ID, map[string]any{"roots": []map[string]any{{"uri": "file:///ok"}}}))
	text, _ := toolText(t, c.read())
	if !strings.Contains(text, "file:///ok") {
		t.Fatalf("got %q", text)
	}
}

func TestCancellation(t *testing.T) {
	r, l := testRouter(t, 0)
	c := connect(t, r, alice(), "fs", nil)
	c.send(7, "tools/call", map[string]any{"name": "slow"})
	time.Sleep(50 * time.Millisecond) // let the request reach the backend
	n, _ := jsonrpc.NewNotification("notifications/cancelled", map[string]any{"requestId": 7})
	c.write(n)
	select {
	case id := <-l.started("fs")[0].cancelled:
		if id == "7" {
			t.Fatal("backend saw the client's id; want the gateway's")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend not told about cancellation")
	}
	// No response for the cancelled request; the session still works.
	if text, _ := toolText(t, c.roundTrip(8, "tools/call", map[string]any{"name": "read_file"})); text != "fs did read_file" {
		t.Fatalf("got %q", text)
	}
}

func TestProgressTokenMapped(t *testing.T) {
	r, _ := testRouter(t, 0)
	c := connect(t, r, alice(), "fs", nil)
	c.send(1, "tools/call", map[string]any{"name": "progress", "_meta": map[string]any{"progressToken": "tok-1"}})
	n := c.read()
	if n.Method != "notifications/progress" || !strings.Contains(string(n.Params), `"progressToken":"tok-1"`) {
		t.Fatalf("progress: %+v", n)
	}
	if text, _ := toolText(t, c.read()); text != "done" {
		t.Fatalf("got %q", text)
	}
}

func TestUnknownServerRejected(t *testing.T) {
	r, _ := testRouter(t, 0)
	cTest, cGw := net.Pipe()
	cc := jsonrpc.NewConn(cTest)
	hello, _ := transport.NewHello("nope")
	go r.ServeClient(context.Background(), jsonrpc.NewConn(cGw), alice(), hello)
	m, err := cc.Read()
	if err != nil || m.Method != "notifications/message" || !strings.Contains(string(m.Params), "unknown server") {
		t.Fatalf("got %+v %v", m, err)
	}
}

func TestNames(t *testing.T) {
	ep := aggregatedEndpoint(map[string]*config.Backend{"fs": {Name: "fs"}, "my-git": {Name: "my-git"}})
	if s, n, ok := ep.resolveName("my-git__log__all"); !ok || s != "my-git" || n != "log__all" {
		t.Errorf("resolveName = %q %q %v", s, n, ok)
	}
	if s, u, ok := ep.resolveURI("mcp+fs:file:///a:b"); !ok || s != "fs" || u != "file:///a:b" {
		t.Errorf("resolveURI = %q %q %v", s, u, ok)
	}
	if _, _, ok := ep.resolveURI("mcp+nope:x"); ok {
		t.Error("unknown server resolved")
	}
	single := singleEndpoint(&config.Backend{Name: "fs"})
	if single.exposeName("fs", "x") != "x" || single.exposeURI("fs", "file:///x") != "file:///x" {
		t.Error("single endpoint must not namespace")
	}
}

func TestLabelElicitation(t *testing.T) {
	out := labelElicitation(json.RawMessage(`{"message":"Your token?","requestedSchema":{}}`), "fs")
	if !strings.Contains(string(out), `"[fs] Your token?"`) {
		t.Fatalf("got %s", out)
	}
}
