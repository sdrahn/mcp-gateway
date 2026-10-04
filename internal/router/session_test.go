package router

import (
	"context"
	"encoding/json"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
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
	return connectWrapped(t, r, p, server, caps, nil)
}

// connectWrapped is connect with the gateway's end of the connection
// wrapped (nil: not).
func connectWrapped(t *testing.T, r *Router, p principal.Principal, server string, caps map[string]any,
	wrap func(jsonrpc.MessageConn) jsonrpc.MessageConn) *client {
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
	var gwConn jsonrpc.MessageConn = jsonrpc.NewConn(cGw)
	if wrap != nil {
		gwConn = wrap(gwConn)
	}
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

// While a call waits for approval, the gateway reports progress itself
// (to a client that asked for it); the backend's progress afterwards is
// shifted so that it keeps increasing.
func TestProgressWhileWaitingForApproval(t *testing.T) {
	r, _ := testRouter(t, 0)
	r.ProgressInterval = 20 * time.Millisecond
	c := connect(t, r, alice(), "fs", map[string]any{"elicitation": map[string]any{}})
	c.send(1, "tools/call", map[string]any{"name": "write_progress", "_meta": map[string]any{"progressToken": 7}})
	var el *jsonrpc.Message
	var waiting []float64
	for el == nil || len(waiting) < 3 {
		m := c.read()
		switch m.Method {
		case "elicitation/create":
			el = m
		case "notifications/progress":
			var p struct {
				ProgressToken json.RawMessage
				Progress      float64
				Message       string
			}
			_ = json.Unmarshal(m.Params, &p)
			if string(p.ProgressToken) != "7" || p.Message != "Waiting for approval of fs/write_progress" {
				t.Fatalf("progress while waiting: %s", m.Params)
			}
			waiting = append(waiting, p.Progress)
		default:
			t.Fatalf("unexpected %+v", m)
		}
	}
	c.write(result(t, el.ID, map[string]any{"action": "accept", "content": map[string]any{"scope": "once"}}))
	last := 0.0
	for {
		m := c.read()
		if m.Method == "notifications/progress" {
			var p struct{ Progress, Total float64 }
			_ = json.Unmarshal(m.Params, &p)
			if p.Total == 0 {
				waiting = append(waiting, p.Progress) // sent before the approval arrived
				continue
			}
			last = p.Progress
			// The backend reports 1 of 2.
			if n := waiting[len(waiting)-1]; p.Progress != n+1 || p.Total != n+2 {
				t.Fatalf("backend progress after %v: %s", waiting, m.Params)
			}
			continue
		}
		if text, isErr := toolText(t, m); isErr || text != "done" {
			t.Fatalf("got %q %v", text, isErr)
		}
		break
	}
	for i, v := range waiting {
		if v != float64(i+1) {
			t.Fatalf("progress while waiting not increasing: %v", waiting)
		}
	}
	if last == 0 {
		t.Fatal("backend progress not passed on")
	}
}

// Clients of MCP 2026-07-28 (the Python SDK 2, mcp-go 1.1 and so Kit)
// probe server/discover first: they get "method not found", fall back to
// initialize, and the probe is not audited as a denial.
func TestDiscoverProbeFallsBack(t *testing.T) {
	r, _ := testRouter(t, 0)
	var logs strings.Builder
	r.Audit = audit.New(&syncWriter{w: &logs})
	cTest, cGw := net.Pipe()
	c := jsonrpc.NewConn(cTest)
	hello, _ := transport.NewHello("fs")
	go r.ServeClient(context.Background(), jsonrpc.NewConn(cGw), alice(), hello)
	probe, _ := jsonrpc.NewRequest(json.RawMessage(`1`), "server/discover", map[string]any{})
	if err := c.Write(probe); err != nil {
		t.Fatal(err)
	}
	m, err := c.Read()
	if err != nil || m.Error == nil || m.Error.Code != jsonrpc.CodeMethodNotFound {
		t.Fatalf("probe: %+v %v", m, err)
	}
	init, _ := jsonrpc.NewRequest(json.RawMessage(`2`), "initialize", map[string]any{
		"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test"},
	})
	if err := c.Write(init); err != nil {
		t.Fatal(err)
	}
	if m, err := c.Read(); err != nil || m.Error != nil || !strings.Contains(string(m.Result), `"protocolVersion":"2025-11-25"`) {
		t.Fatalf("initialize after probe: %+v %v", m, err)
	}
	_ = c.Close()
	if strings.Contains(logs.String(), "server/discover") {
		t.Errorf("probe audited: %s", logs.String())
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

func TestObligations(t *testing.T) {
	r, _ := testRouter(t, 0)
	var logs strings.Builder
	r.Audit = audit.New(&syncWriter{w: &logs})
	c := connect(t, r, alice(), "fs", nil)
	call := func(id int, name string, args map[string]any) (string, bool) {
		return toolText(t, c.roundTrip(id, "tools/call", map[string]any{"name": name, "arguments": args}))
	}

	if text, isErr := call(1, "read_secret", nil); isErr || text != "user=bob "+pep.Redacted+" done" {
		t.Errorf("redaction: %q %v", text, isErr)
	}
	if text, isErr := call(2, "read_big", nil); !isErr || !strings.Contains(text, "output withheld") {
		t.Errorf("size limit: %q %v", text, isErr)
	}
	if _, isErr := call(3, "read_limited", nil); isErr {
		t.Error("first limited call refused")
	}
	if _, isErr := call(4, "read_limited", nil); isErr {
		t.Error("second limited call refused")
	}
	if text, isErr := call(5, "read_limited", nil); !isErr || !strings.Contains(text, "rate limit") {
		t.Errorf("rate limit: %q %v", text, isErr)
	}
	if _, isErr := call(6, "read_path", map[string]any{"path": "/ok/a"}); isErr {
		t.Error("constrained call with a valid argument refused")
	}
	if text, isErr := call(7, "read_path", map[string]any{"path": "/etc/passwd"}); !isErr || !strings.Contains(text, "violates a constraint") {
		t.Errorf("arg constraint: %q %v", text, isErr)
	}
	if _, isErr := call(8, "read_audited", map[string]any{"q": "visible"}); isErr {
		t.Error("audited call refused")
	}
	if text, isErr := call(9, "read_broken", nil); !isErr || !strings.Contains(text, "invalid policy decision") {
		t.Errorf("malformed obligation must deny: %q %v", text, isErr)
	}
	out := logs.String()
	if !strings.Contains(out, `"args":{"q":"visible"}`) {
		t.Errorf("full audit missing args: %s", out)
	}
	if strings.Contains(out, `"args":{"path"`) {
		t.Errorf("digest audit logged args verbatim: %s", out)
	}
	if !regexp.MustCompile(`"decision_id":"[0-9a-f]{32}"`).MatchString(out) {
		t.Errorf("audit records lack decision ids: %s", out)
	}
}

type syncWriter struct {
	mu sync.Mutex
	w  *strings.Builder
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

func TestLabelElicitation(t *testing.T) {
	out := labelElicitation(json.RawMessage(`{"message":"Your token?","requestedSchema":{}}`), "fs")
	if !strings.Contains(string(out), `"[fs] Your token?"`) {
		t.Fatalf("got %s", out)
	}
}

func TestElicitationArgs(t *testing.T) {
	for _, tc := range []struct {
		schema    string
		sensitive bool
	}{
		{`{"color":{"type":"string"}}`, false},
		{`{"compass_heading":{"type":"string"},"spinner":{"type":"string"}}`, false},
		{`{"user_password":{"type":"string"}}`, true},
		{`{"value":{"type":"string","title":"GitHub token"}}`, true},
		{`{"x":{"type":"string","description":"Your API key"}}`, true},
		{`{"code":{"type":"string","title":"2FA code"}}`, true},
		{`{"user_pin":{"type":"string"}}`, true},
	} {
		args := elicitationArgs(json.RawMessage(`{"message":"m","requestedSchema":{"type":"object","properties":` + tc.schema + `}}`))
		if args["sensitive"] != tc.sensitive || args["mode"] != "form" {
			t.Errorf("%s: args %v", tc.schema, args)
		}
	}
	args := elicitationArgs(json.RawMessage(`{"mode":"url","message":"m","url":"https://x/y","elicitationId":"1"}`))
	if args["mode"] != "url" || args["url"] != "https://x/y" {
		t.Errorf("url mode: %v", args)
	}
}

func TestSensitiveBackendElicitationDenied(t *testing.T) {
	r, _ := testRouter(t, 0)
	c := connect(t, r, alice(), "fs", map[string]any{"elicitation": map[string]any{}})

	// A harmless question is relayed to the client ...
	c.send(1, "tools/call", map[string]any{"name": "ask_color"})
	req := c.read()
	if req.Method != "elicitation/create" || !strings.Contains(string(req.Params), "[fs]") {
		t.Fatalf("want relayed elicitation, got %+v", req)
	}
	c.write(result(t, req.ID, map[string]any{"action": "accept", "content": map[string]any{"color": "blue"}}))
	if text, _ := toolText(t, c.read()); !strings.Contains(text, "blue") {
		t.Fatalf("got %q", text)
	}
	// ... one asking for a password never reaches it.
	text, _ := toolText(t, c.roundTrip(2, "tools/call", map[string]any{"name": "ask_secret"}))
	if !strings.Contains(text, "denied by mcp-gateway policy") {
		t.Fatalf("got %q", text)
	}
}

func TestPolicyChangedNotifiesSessions(t *testing.T) {
	r, _ := testRouter(t, 0)
	c1 := connect(t, r, alice(), "fs", nil)
	c2 := connect(t, r, alice(), "", nil)

	// A changing fingerprint triggers exactly one broadcast per change.
	fps := []string{"a", "a", "b", "b"}
	var i int
	var mu sync.Mutex
	changes := make(chan struct{}, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.WatchPolicy(ctx, func() time.Duration { return 10 * time.Millisecond }, func(context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		fp := fps[min(i, len(fps)-1)]
		i++
		return fp, nil
	}, func() { changes <- struct{}{} })

	for _, c := range []*client{c1, c2} {
		var got []string
		for range 3 {
			got = append(got, c.read().Method)
		}
		if strings.Join(got, ",") != "notifications/tools/list_changed,notifications/prompts/list_changed,notifications/resources/list_changed" {
			t.Fatalf("notifications %v", got)
		}
	}
	<-changes
	time.Sleep(50 * time.Millisecond)
	if len(changes) != 0 {
		t.Fatal("more than one change reported")
	}
	// After a session ends it is no longer notified.
	c1.close()
	r.PolicyChanged()
	if m := c2.read(); m.Method != "notifications/tools/list_changed" {
		t.Fatalf("got %+v", m)
	}
}

func TestSingleEndpointAdvertisesListChanged(t *testing.T) {
	caps := withListChanged(map[string]json.RawMessage{
		"tools":        json.RawMessage(`{}`),
		"resources":    json.RawMessage(`{"subscribe":true}`),
		"logging":      json.RawMessage(`{}`),
		"tasks":        json.RawMessage(`{"requests":{"tools":{"call":{}}}}`),
		"experimental": json.RawMessage(`{"x":{}}`),
	})
	if string(caps["tools"]) != `{"listChanged":true}` || string(caps["resources"]) != `{"listChanged":true,"subscribe":true}` ||
		string(caps["logging"]) != `{}` {
		t.Fatalf("caps %s %s %s", caps["tools"], caps["resources"], caps["logging"])
	}
	if _, ok := caps["prompts"]; ok {
		t.Fatal("capability added that the backend does not have")
	}
	if _, ok := caps["tasks"]; ok {
		t.Fatal("tasks passed on, which the gateway does not route")
	}
	if _, ok := caps["experimental"]; ok {
		t.Fatal("experimental capabilities passed on")
	}
}

// A client asking for a task gets a plain result; the backend never sees
// the task request.
func TestTaskRequestRunsSynchronously(t *testing.T) {
	r, _ := testRouter(t, 0)
	c := connect(t, r, alice(), "fs", nil)
	m := c.roundTrip(1, "tools/call", map[string]any{"name": "read_task", "task": map[string]any{"ttl": 60000}})
	if text, isErr := toolText(t, m); isErr || text != "no task" {
		t.Fatalf("got %q %v", text, isErr)
	}
}

type goneElicitor struct{}

func (goneElicitor) SupportsForm() bool { return false }
func (goneElicitor) SupportsURL() bool  { return false }
func (goneElicitor) Elicit(context.Context, any) (broker.ElicitResult, error) {
	return broker.ElicitResult{}, context.Canceled
}
func (goneElicitor) Notify(string, any) {}

func TestOnceGrantFromApprovalWithoutWaitingCall(t *testing.T) {
	r, _ := testRouter(t, 0)
	b := mustBroker(t, broker.Options{Timeout: 5 * time.Second, OOB: true})
	r.Broker = b
	var logs strings.Builder
	r.Audit = audit.New(&syncWriter{w: &logs})
	p := alice()

	// An approval whose call went away, approved "once" afterwards.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_, _ = b.Approve(ctx, goneElicitor{}, pep.Input{Principal: p, Action: "tools.call",
			Resource: pep.Resource{Server: "fs", Kind: "tool", Name: "write_file"}},
			pep.AskSpec{Channel: pep.ChannelOOB, Scopes: []string{"once"}})
	}()
	root := broker.Approver{Name: "root", UID: 0}
	var id string
	for i := 0; i < 400 && id == ""; i++ {
		if ps := b.ListPending(context.Background(), root); len(ps) == 1 {
			id = ps[0].ID
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	for i := 0; i < 400; i++ {
		if ps := b.ListPending(context.Background(), root); len(ps) == 1 && !ps[0].Waiting {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	g, err := b.Resolve(context.Background(), root, id, true, "once")
	if err != nil {
		t.Fatal(err)
	}

	// The next attempt uses it up.
	c := connect(t, r, p, "fs", nil)
	if text, isErr := toolText(t, c.roundTrip(1, "tools/call", map[string]any{"name": "write_file"})); isErr || text != "fs did write_file" {
		t.Fatalf("first call: %q %v", text, isErr)
	}
	if !strings.Contains(logs.String(), `"grant":"`+g.ID+`"`) {
		t.Errorf("audit record lacks the once grant: %s", logs.String())
	}
	if _, ok := b.TakeOnce(p, "fs", "write_file"); ok {
		t.Fatal("once grant not used up")
	}
}

func TestPseudonymization(t *testing.T) {
	r, l := testRouter(t, 0)
	var logs strings.Builder
	r.Audit = audit.New(&syncWriter{w: &logs})
	c := connect(t, r, alice(), "fs", map[string]any{"sampling": map[string]any{}})
	call := func(c *client, id int, name string, args map[string]any) (string, bool) {
		return toolText(t, c.roundTrip(id, "tools/call", map[string]any{"name": name, "arguments": args}))
	}

	// Field rules and detectors, also inside JSON returned as text.
	text, isErr := call(c, 1, "read_customer", nil)
	want := `{"email":"[EMAIL_1]","id":"[CUSTOMER_1]","manager":"[EMAIL_2]","name":"[PERSON_1]"}`
	if isErr || text != want {
		t.Fatalf("pseudonymized result:\n got %s\nwant %s", text, want)
	}

	// Named arguments are re-identified (with their type), others not.
	if _, isErr := call(c, 2, "update_customer", map[string]any{"id": "[CUSTOMER_1]", "note": "write to [EMAIL_1]", "name": "[PERSON_1]"}); isErr {
		t.Fatal("update refused")
	}
	fs := l.started("fs")[0]
	if got := fs.updateArgs(); got != `{"id":4711,"name":"[PERSON_1]","note":"write to alice@example.com"}` {
		t.Errorf("backend got %s", got)
	}

	// Policy decides again on the real values.
	text, isErr = call(c, 3, "update_customer", map[string]any{"id": "[CUSTOMER_1]", "note": "[EMAIL_2]"})
	if !isErr || !strings.Contains(text, "policy did not accept the re-identified arguments") {
		t.Errorf("second decision: %q %v", text, isErr)
	}

	// Another session's tokens mean nothing here.
	c2 := connect(t, r, alice(), "fs", nil)
	if _, isErr := call(c2, 1, "update_customer", map[string]any{"id": "[CUSTOMER_1]"}); isErr {
		t.Fatal("update in second session refused")
	}
	if got := fs.updateArgs(); got != `{"id":"[CUSTOMER_1]"}` {
		t.Errorf("token of another session re-identified: %s", got)
	}

	// Sampling requests are pseudonymized before they reach the client's model.
	c.send(4, "tools/call", map[string]any{"name": "ask_llm"})
	req := c.read()
	if req.Method != "sampling/createMessage" {
		t.Fatalf("want sampling request, got %+v", req)
	}
	if s := string(req.Params); strings.Contains(s, "carol@") || !strings.Contains(s, "the mail from [EMAIL_3]") {
		t.Errorf("sampling request not pseudonymized: %s", s)
	}
	c.write(result(t, req.ID, map[string]any{"role": "assistant", "content": map[string]any{"type": "text", "text": "fine"}}))
	if text, _ := toolText(t, c.read()); !strings.Contains(text, "fine") {
		t.Errorf("sampling result: %q", text)
	}

	out := logs.String()
	for _, want := range []string{`"event":"mcp-pseudonymize"`, `"values":"CUSTOMER:1 EMAIL:2 PERSON:1"`, `"reidentified":2`} {
		if !strings.Contains(out, want) {
			t.Errorf("audit lacks %s: %s", want, out)
		}
	}
	if strings.Contains(out, "alice@example.com") || strings.Contains(out, "Alice Doe") {
		t.Errorf("audit contains personal data: %s", out)
	}
}

// Parameters a server could read differently from the gateway are
// refused before policy is asked: repeated keys, keys differing only in
// case from one the gateway reads or from a declared argument, also
// without a tools/list in the session first.
func TestParamKeysRefused(t *testing.T) {
	r, _ := testRouter(t, 0)
	c := connect(t, r, alice(), "fs", nil)
	for i, tc := range []struct{ params, want string }{
		{`{"name":"read_file","arguments":{"path":"/home/alice/x","Path":"/etc/shadow"}}`, `differ only in case`},
		{`{"name":"read_file","arguments":{"path":"/home/alice/x","path":"/etc/shadow"}}`, `appears twice`},
		{`{"name":"read_file","Arguments":{"path":"/etc/shadow"}}`, `key "Arguments" differs from "arguments" only in case`},
		{`{"Name":"read_file","name":"read_file"}`, `differ only in case`},
		{`{"name":"read_file","arguments":{"Path":"/etc/shadow"}}`, `arguments: key "Path" differs from "path" only in case`},
		{`{"name":"read_file","_meta":{"ProgressToken":1}}`, `_meta: key "ProgressToken"`},
	} {
		m := c.roundTrip(10+i, "tools/call", json.RawMessage(tc.params))
		if m.Error == nil || m.Error.Code != jsonrpc.CodeInvalidParams || !strings.Contains(m.Error.Message, tc.want) {
			t.Errorf("%s: got %+v %+v", tc.params, m.Error, string(m.Result))
		}
	}
	// Declared names, other arguments and nested objects pass.
	m := c.roundTrip(30, "tools/call", json.RawMessage(`{"name":"read_file","arguments":{"path":"/home/alice/x","mode":"r","extra":{"Path":1}}}`))
	if text, isErr := toolText(t, m); isErr || text != "fs did read_file" {
		t.Fatalf("got %q %v %+v", text, isErr, m.Error)
	}
}

// An update of a subscribed resource reaches the client only while policy
// still allows the subscription.
func TestResourceUpdatesFollowPolicy(t *testing.T) {
	r, _ := testRouter(t, 0)
	c := connect(t, r, alice(), "fs", nil)
	c.send(1, "resources/subscribe", map[string]any{"uri": "file:///ok/a.txt"})
	var updates []string
	gotResponse := false
	deadline := time.After(3 * time.Second)
	for !gotResponse || len(updates) == 0 {
		select {
		case m := <-c.msgs:
			switch {
			case m.Key() == "1":
				if m.Error != nil {
					t.Fatalf("subscribe: %+v", m.Error)
				}
				gotResponse = true
			case m.Method == "notifications/resources/updated":
				updates = append(updates, string(m.Params))
			}
		case <-deadline:
			t.Fatalf("response %v, updates %v", gotResponse, updates)
		}
	}
	// The second update (file:///secret) follows the first; it must not
	// arrive.
	select {
	case m := <-c.msgs:
		t.Fatalf("unexpected message %s %s", m.Method, m.Params)
	case <-time.After(300 * time.Millisecond):
	}
	if len(updates) != 1 || !strings.Contains(updates[0], "file:///ok/a.txt") {
		t.Fatalf("updates %v", updates)
	}
}

func TestAggregatedInstructionsPointToGatewayAdmin(t *testing.T) {
	plain := aggregatedInstructions(aggregatedEndpoint(map[string]*config.Backend{"fs": {Name: "fs"}}))
	if strings.Contains(plain, "gateway-admin") || strings.Contains(plain, "gateway-docs") {
		t.Errorf("names servers that are not there: %s", plain)
	}
	got := aggregatedInstructions(aggregatedEndpoint(map[string]*config.Backend{
		"fs": {Name: "fs"}, "gateway-admin": {Name: "gateway-admin"}, "gateway-docs": {Name: "gateway-docs"},
	}))
	for _, want := range []string{"gateway-admin__show_config", "gateway-admin__check_config", "server gateway-docs"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in %s", want, got)
		}
	}
}

// relatedConn records which client request each message the gateway sends
// belongs to (as an HTTP session would put it on that request's stream).
type relatedConn struct {
	jsonrpc.MessageConn
	mu      sync.Mutex
	related map[string]string // method → client request id
}

func (c *relatedConn) WriteRelated(m *jsonrpc.Message, id json.RawMessage) error {
	c.mu.Lock()
	c.related[m.Method] = string(id)
	c.mu.Unlock()
	return c.Write(m)
}

func (c *relatedConn) of(method string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.related[method]
}

// What a call makes the gateway send (the backend's progress, its
// elicitation) belongs to that call's request.
func TestMessagesRelatedToTheirRequest(t *testing.T) {
	r, _ := testRouter(t, 0)
	rc := &relatedConn{related: map[string]string{}}
	c := connectWrapped(t, r, alice(), "fs", map[string]any{"elicitation": map[string]any{}},
		func(mc jsonrpc.MessageConn) jsonrpc.MessageConn { rc.MessageConn = mc; return rc })

	c.send(7, "tools/call", map[string]any{"name": "progress", "_meta": map[string]any{"progressToken": "tok-1"}})
	if n := c.read(); n.Method != "notifications/progress" {
		t.Fatalf("got %+v", n)
	}
	c.read()
	if got := rc.of("notifications/progress"); got != "7" {
		t.Fatalf("progress related to %q", got)
	}

	c.send(8, "tools/call", map[string]any{"name": "ask_color"})
	req := c.read()
	if req.Method != "elicitation/create" {
		t.Fatalf("got %+v", req)
	}
	c.write(result(t, req.ID, map[string]any{"action": "accept", "content": map[string]any{"color": "blue"}}))
	c.read()
	if got := rc.of("elicitation/create"); got != "8" {
		t.Fatalf("elicitation related to %q", got)
	}
}

// The gateway's own approval dialog belongs to the call that waits for it.
func TestApprovalElicitationRelatedToItsRequest(t *testing.T) {
	r, _ := testRouter(t, 0)
	rc := &relatedConn{related: map[string]string{}}
	c := connectWrapped(t, r, alice(), "fs", map[string]any{"elicitation": map[string]any{}},
		func(mc jsonrpc.MessageConn) jsonrpc.MessageConn { rc.MessageConn = mc; return rc })
	c.send(9, "tools/call", map[string]any{"name": "write_file"})
	el := c.read()
	if el.Method != "elicitation/create" {
		t.Fatalf("got %+v", el)
	}
	c.write(result(t, el.ID, map[string]any{"action": "accept", "content": map[string]any{"scope": "once"}}))
	c.read()
	if got := rc.of("elicitation/create"); got != "9" {
		t.Fatalf("approval related to %q", got)
	}
}
