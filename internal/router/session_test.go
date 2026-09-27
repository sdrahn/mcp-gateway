package router

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// fakePDP: read_* allowed, write_* needs form approval, everything else
// denied; only non-denied tools are visible. Backend requests: roots.list
// allowed, everything else denied.
type fakePDP struct{ inputs chan pep.Input }

func (f *fakePDP) Decide(_ context.Context, in pep.Input) (pep.Decision, error) {
	if f.inputs != nil {
		f.inputs <- in
	}
	switch {
	case in.Action == "roots.list":
		return pep.Decision{Effect: pep.Allow}, nil
	case in.Action != "tools.call":
		return pep.Decision{Effect: pep.Deny, Reason: "no"}, nil
	case strings.HasPrefix(in.Resource.Name, "read_"):
		return pep.Decision{Effect: pep.Allow}, nil
	case strings.HasPrefix(in.Resource.Name, "write_"):
		if len(in.Grants) > 0 {
			return pep.Decision{Effect: pep.Allow}, nil
		}
		return pep.Decision{Effect: pep.Ask, Ask: &pep.AskSpec{Channel: pep.ChannelForm, Scopes: []string{"once", "session"}}}, nil
	}
	return pep.Decision{Effect: pep.Deny, Reason: "not yours"}, nil
}

func (f *fakePDP) Visible(ctx context.Context, p principal.Principal, rs []pep.Resource) ([]pep.Resource, error) {
	var out []pep.Resource
	for _, r := range rs {
		if d, _ := f.Decide(ctx, pep.Input{Principal: p, Action: "tools.call", Resource: r}); d.Effect != pep.Deny {
			out = append(out, r)
		}
	}
	return out, nil
}

// fakeBackend answers like a trivial MCP server and records tool calls.
func fakeBackend(t *testing.T, c *jsonrpc.Conn, calls chan<- string) {
	t.Helper()
	for {
		m, err := c.Read()
		if err != nil {
			return
		}
		if !m.IsRequest() {
			continue
		}
		var result any
		switch m.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "fake"}}
		case "tools/list":
			result = map[string]any{"tools": []map[string]any{
				{"name": "read_file", "inputSchema": map[string]any{"type": "object"}},
				{"name": "write_file", "inputSchema": map[string]any{"type": "object"}, "annotations": map[string]any{"destructiveHint": true}},
				{"name": "delete_file", "inputSchema": map[string]any{"type": "object"}},
			}, "nextCursor": "c2"}
		case "tools/call":
			var p struct{ Name string }
			_ = json.Unmarshal(m.Params, &p)
			calls <- p.Name
			result = map[string]any{"content": []map[string]any{{"type": "text", "text": "did " + p.Name}}}
		case "resources/list":
			result = map[string]any{"resources": []map[string]any{{"uri": "file:///etc/passwd", "name": "passwd"}}}
		default:
			_ = c.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeMethodNotFound, "nope"))
			continue
		}
		r, _ := jsonrpc.NewResult(m.ID, result)
		_ = c.Write(r)
	}
}

type harness struct {
	t       *testing.T
	client  *jsonrpc.Conn // test side of the client connection
	backend *jsonrpc.Conn // test side of the backend connection (when no fake backend)
	calls   chan string
	cancel  context.CancelFunc
	pdp     *fakePDP
}

func newHarness(t *testing.T, withFakeBackend bool) *harness {
	t.Helper()
	cTest, cGw := net.Pipe()
	bGw, bTest := net.Pipe()
	h := &harness{t: t, client: jsonrpc.NewConn(cTest), calls: make(chan string, 10), pdp: &fakePDP{}}
	backendTest := jsonrpc.NewConn(bTest)
	if withFakeBackend {
		go fakeBackend(t, backendTest, h.calls)
	} else {
		h.backend = backendTest
	}
	s := NewSession(SessionConfig{
		Principal: principal.Principal{Sub: "alice", SessionID: "s1", Transport: principal.TransportUnix},
		Server:    "fs",
		Client:    jsonrpc.NewConn(cGw),
		Backend:   jsonrpc.NewConn(bGw),
		PDP:       h.pdp,
		Broker:    broker.New(time.Second),
	})
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { _ = s.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = h.client.Close()
		_ = backendTest.Close()
	})
	return h
}

func (h *harness) send(id int, method string, params any) {
	h.t.Helper()
	m, err := jsonrpc.NewRequest(json.RawMessage(json.Number(itoa(id))), method, params)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.client.Write(m); err != nil {
		h.t.Fatal(err)
	}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

// read returns the next message from the gateway to the client.
func (h *harness) read() *jsonrpc.Message {
	h.t.Helper()
	type res struct {
		m   *jsonrpc.Message
		err error
	}
	ch := make(chan res, 1)
	go func() { m, err := h.client.Read(); ch <- res{m, err} }()
	select {
	case r := <-ch:
		if r.err != nil {
			h.t.Fatal(r.err)
		}
		return r.m
	case <-time.After(2 * time.Second):
		h.t.Fatal("timeout waiting for gateway message")
	}
	return nil
}

func (h *harness) initialize(caps map[string]any) {
	h.t.Helper()
	h.send(1, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": caps, "clientInfo": map[string]any{"name": "test"}})
	if m := h.read(); m.Error != nil || m.Key() != "1" {
		h.t.Fatalf("initialize: %+v", m)
	}
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

func TestToolsListFiltered(t *testing.T) {
	h := newHarness(t, true)
	h.initialize(nil)
	h.send(2, "tools/list", map[string]any{})
	m := h.read()
	var r struct {
		Tools []struct {
			Name string
		}
		NextCursor string
	}
	if err := json.Unmarshal(m.Result, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Tools) != 2 || r.Tools[0].Name != "read_file" || r.Tools[1].Name != "write_file" || r.NextCursor != "c2" {
		t.Fatalf("tools/list = %s", m.Result)
	}
}

func TestResourcesListHidden(t *testing.T) {
	h := newHarness(t, true)
	h.initialize(nil)
	h.send(2, "resources/list", map[string]any{})
	if m := h.read(); string(m.Result) != `{"resources":[]}` {
		t.Fatalf("resources/list = %s", m.Result)
	}
}

func TestAllowedCallForwarded(t *testing.T) {
	h := newHarness(t, true)
	h.initialize(nil)
	h.send(2, "tools/call", map[string]any{"name": "read_file", "arguments": map[string]any{"path": "/x"}})
	if text, isErr := toolText(t, h.read()); isErr || text != "did read_file" {
		t.Fatalf("got %q isError=%v", text, isErr)
	}
}

func TestDeniedCallNotForwarded(t *testing.T) {
	h := newHarness(t, true)
	h.initialize(nil)
	h.send(2, "tools/call", map[string]any{"name": "delete_file"})
	text, isErr := toolText(t, h.read())
	if !isErr || !strings.Contains(text, "not yours") {
		t.Fatalf("got %q isError=%v", text, isErr)
	}
	select {
	case c := <-h.calls:
		t.Fatalf("backend received %s", c)
	default:
	}
}

func TestOtherEnforcedMethodDenied(t *testing.T) {
	h := newHarness(t, true)
	h.initialize(nil)
	h.send(2, "resources/read", map[string]any{"uri": "file:///etc/passwd"})
	if m := h.read(); m.Error == nil || m.Error.Code != jsonrpc.CodeForbidden {
		t.Fatalf("got %+v", m)
	}
}

func TestUnknownMethodDenied(t *testing.T) {
	h := newHarness(t, true)
	h.initialize(nil)
	h.send(2, "tools/secret", map[string]any{})
	if m := h.read(); m.Error == nil || m.Error.Code != jsonrpc.CodeMethodNotFound {
		t.Fatalf("got %+v", m)
	}
}

func TestAskWithoutElicitationSupportDenied(t *testing.T) {
	h := newHarness(t, true)
	h.initialize(map[string]any{})
	h.send(2, "tools/call", map[string]any{"name": "write_file"})
	text, isErr := toolText(t, h.read())
	if !isErr || !strings.Contains(text, "approval via form required") {
		t.Fatalf("got %q isError=%v", text, isErr)
	}
}

// answerElicitation reads the gateway's elicitation/create and answers it.
func (h *harness) answerElicitation(action, scope string) {
	h.t.Helper()
	m := h.read()
	if m.Method != "elicitation/create" || !strings.HasPrefix(m.Key(), `"mcpgw-`) {
		h.t.Fatalf("want elicitation, got %+v", m)
	}
	var p broker.ElicitParams
	if err := json.Unmarshal(m.Params, &p); err != nil || !strings.Contains(p.Message, "write_file") {
		h.t.Fatalf("elicitation params %s", m.Params)
	}
	result := map[string]any{"action": action}
	if scope != "" {
		result["content"] = map[string]any{"scope": scope}
	}
	r, _ := jsonrpc.NewResult(m.ID, result)
	if err := h.client.Write(r); err != nil {
		h.t.Fatal(err)
	}
}

func TestAskApprovedForSession(t *testing.T) {
	h := newHarness(t, true)
	h.initialize(map[string]any{"elicitation": map[string]any{}})

	h.send(2, "tools/call", map[string]any{"name": "write_file"})
	h.answerElicitation("accept", "session")
	if text, isErr := toolText(t, h.read()); isErr || text != "did write_file" {
		t.Fatalf("got %q isError=%v", text, isErr)
	}
	// Second call: the session grant applies, no new elicitation.
	h.send(3, "tools/call", map[string]any{"name": "write_file"})
	if m := h.read(); m.Key() != "3" {
		t.Fatalf("expected direct result, got %+v", m)
	}
}

func TestAskApprovedOnce(t *testing.T) {
	h := newHarness(t, true)
	h.initialize(map[string]any{"elicitation": map[string]any{"form": map[string]any{}}})

	h.send(2, "tools/call", map[string]any{"name": "write_file"})
	h.answerElicitation("accept", "once")
	if _, isErr := toolText(t, h.read()); isErr {
		t.Fatal("first call failed")
	}
	h.send(3, "tools/call", map[string]any{"name": "write_file"})
	h.answerElicitation("decline", "")
	if text, isErr := toolText(t, h.read()); !isErr || !strings.Contains(text, "declined") {
		t.Fatalf("got %q isError=%v", text, isErr)
	}
}

func TestBackendRequests(t *testing.T) {
	h := newHarness(t, false)
	// Backend asks the client for its roots (allowed) and to sample
	// (denied).
	roots, _ := jsonrpc.NewRequest(json.RawMessage(`5`), "roots/list", map[string]any{})
	if err := h.backend.Write(roots); err != nil {
		t.Fatal(err)
	}
	m := h.read()
	if m.Method != "roots/list" || m.Key() == "5" {
		t.Fatalf("forwarded roots/list: %+v", m)
	}
	r, _ := jsonrpc.NewResult(m.ID, map[string]any{"roots": []any{}})
	if err := h.client.Write(r); err != nil {
		t.Fatal(err)
	}
	back, err := h.backend.Read()
	if err != nil || back.Key() != "5" || back.Error != nil {
		t.Fatalf("response to backend: %+v %v", back, err)
	}

	sampling, _ := jsonrpc.NewRequest(json.RawMessage(`6`), "sampling/createMessage", map[string]any{})
	if err := h.backend.Write(sampling); err != nil {
		t.Fatal(err)
	}
	back, err = h.backend.Read()
	if err != nil || back.Key() != "6" || back.Error == nil || back.Error.Code != jsonrpc.CodeForbidden {
		t.Fatalf("sampling response: %+v %v", back, err)
	}
}

func TestLabelElicitation(t *testing.T) {
	out := labelElicitation(json.RawMessage(`{"message":"Your token?","requestedSchema":{}}`), "fs")
	if !strings.Contains(string(out), `"[fs] Your token?"`) {
		t.Fatalf("got %s", out)
	}
}
