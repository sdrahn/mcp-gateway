package router

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
)

// logConn records the client request each log message goes with, by the
// message's data.
type logConn struct {
	jsonrpc.MessageConn
	mu  sync.Mutex
	req map[string]string
}

func (c *logConn) WriteRelated(m *jsonrpc.Message, id json.RawMessage) error {
	var p struct{ Data, Message string }
	_ = json.Unmarshal(m.Params, &p)
	c.mu.Lock()
	switch m.Method {
	case "notifications/message":
		c.req[p.Data] = string(id)
	case "elicitation/create":
		c.req[p.Message] = string(id)
	}
	c.mu.Unlock()
	return c.Write(m)
}

// of returns the request the message with data went with (an
// elicitation's message, which names its server, ends with it).
func (c *logConn) of(data string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for d, req := range c.req {
		if d == data || strings.HasSuffix(d, " "+data) {
			return req
		}
	}
	return ""
}

// twoLoggedCalls makes two calls of read_logged at once on server, and
// returns the log messages the client got.
func twoLoggedCalls(t *testing.T, r *Router, server string) (*logConn, []*jsonrpc.Message) {
	t.Helper()
	lc := &logConn{req: map[string]string{}}
	c := connectWrapped(t, r, alice(), server, map[string]any{},
		func(mc jsonrpc.MessageConn) jsonrpc.MessageConn { lc.MessageConn = mc; return lc })
	c.send(1, "logging/setLevel", map[string]any{"level": "debug"})
	c.read()
	c.send(11, "tools/call", map[string]any{"name": "read_logged", "arguments": map[string]any{"tag": "first"}})
	c.send(12, "tools/call", map[string]any{"name": "read_logged", "arguments": map[string]any{"tag": "second"}})
	var logs []*jsonrpc.Message
	results := 0
	deadline := time.Now().Add(10 * time.Second)
	for results < 2 && time.Now().Before(deadline) {
		m := c.read()
		switch {
		case m.Method == "notifications/message":
			logs = append(logs, m)
		case m.IsResponse():
			results++
		}
	}
	if results < 2 || len(logs) != 2 {
		t.Fatalf("%d results, logs %v", results, logs)
	}
	return lc, logs
}

// With two calls in flight on an HTTP server, each log message goes with
// the call whose stream it came on (mcp-http-connector names it,
// jsonrpc.RelatedMeta); the name does not reach the client.
func TestHTTPServerMessagesFollowTheirCall(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	r.Backends["httplog"] = &config.Backend{Name: "httplog", Isolation: config.IsolationPrincipal, URL: "https://mcp.example.com/mcp"}
	lc, logs := twoLoggedCalls(t, r, "httplog")
	if a, b := lc.of("first"), lc.of("second"); a != "11" || b != "12" {
		t.Errorf("log messages went with %q and %q, want 11 and 12", a, b)
	}
	for _, m := range logs {
		if strings.Contains(string(m.Params), jsonrpc.RelatedMeta) {
			t.Errorf("the client got the connector's name: %s", m.Params)
		}
	}
}

// So does a request of the server (an elicitation) during either call.
func TestHTTPServerRequestsFollowTheirCall(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	r.Backends["httpask"] = &config.Backend{Name: "httpask", Isolation: config.IsolationPrincipal, URL: "https://mcp.example.com/mcp"}
	lc := &logConn{req: map[string]string{}}
	c := connectWrapped(t, r, alice(), "httpask", map[string]any{"elicitation": map[string]any{}},
		func(mc jsonrpc.MessageConn) jsonrpc.MessageConn { lc.MessageConn = mc; return lc })
	c.send(21, "tools/call", map[string]any{"name": "ask_logged", "arguments": map[string]any{"tag": "first"}})
	c.send(22, "tools/call", map[string]any{"name": "ask_logged", "arguments": map[string]any{"tag": "second"}})
	results := 0
	for results < 2 {
		m := c.read()
		switch {
		case m.Method == "elicitation/create":
			if strings.Contains(string(m.Params), jsonrpc.RelatedMeta) {
				t.Errorf("the client got the connector's name: %s", m.Params)
			}
			c.write(result(t, m.ID, map[string]any{"action": "accept", "content": map[string]any{"ok": true}}))
		case m.IsResponse():
			if text, isErr := toolText(t, m); isErr || !strings.Contains(text, `"accept"`) {
				t.Fatalf("call: %q", text)
			}
			results++
		}
	}
	if a, b := lc.of("first"), lc.of("second"); a != "21" || b != "22" {
		t.Errorf("elicitations went with %q and %q, want 21 and 22", a, b)
	}
}

// A stdio server's naming is not trusted (it could name any request):
// with two calls in flight, its log messages go with neither, as before;
// the name is removed all the same.
func TestStdioServerMessagesNotNamed(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	lc, logs := twoLoggedCalls(t, r, "fs")
	if a, b := lc.of("first"), lc.of("second"); a != "" || b != "" {
		t.Errorf("log messages went with %q and %q", a, b)
	}
	for _, m := range logs {
		if strings.Contains(string(m.Params), jsonrpc.RelatedMeta) {
			t.Errorf("the client got the server's name: %s", m.Params)
		}
	}
}

// SetRelated and TakeRelated: the id in the params' _meta, added and
// removed, other _meta kept; an emptied _meta goes.
func TestRelatedMeta(t *testing.T) {
	raw := jsonrpc.SetRelated(json.RawMessage(`{"jsonrpc":"2.0","method":"notifications/message","params":{"_meta":{"x":1},"data":"d"}}`), json.RawMessage(`7`))
	var m jsonrpc.Message
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if id := jsonrpc.TakeRelated(&m); string(id) != "7" || string(m.Params) != `{"_meta":{"x":1},"data":"d"}` {
		t.Errorf("%s %s", id, m.Params)
	}
	raw = jsonrpc.SetRelated(json.RawMessage(`{"jsonrpc":"2.0","id":"b-1","method":"elicitation/create"}`), json.RawMessage(`"r"`))
	m = jsonrpc.Message{}
	_ = json.Unmarshal(raw, &m)
	if id := jsonrpc.TakeRelated(&m); string(id) != `"r"` || string(m.Params) != `{}` {
		t.Errorf("no params: %s %s", id, m.Params)
	}
	if id := jsonrpc.TakeRelated(&jsonrpc.Message{Params: json.RawMessage(`[1]`)}); id != nil {
		t.Errorf("array params: %s", id)
	}
}
