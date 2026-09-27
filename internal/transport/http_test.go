package transport

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// fakeAuth accepts "alice", "bob" and "noscope" as tokens.
type fakeAuth struct{}

func (fakeAuth) Authenticate(_ context.Context, token string, _ *x509.Certificate) (principal.Principal, error) {
	switch token {
	case "alice", "bob":
		return principal.Principal{Sub: token, Issuer: "https://idp", Transport: principal.TransportHTTP}, nil
	case "noscope":
		return principal.Principal{}, ErrInsufficientScope
	}
	return principal.Principal{}, ErrInvalidToken
}

// echoServe is a tiny MCP server: initialize answers with the endpoint,
// "ask" first sends an elicitation to the client, "notify" sends a
// notification first, "later" answers and then sends a notification.
func echoServe(_ context.Context, c jsonrpc.MessageConn, p principal.Principal, first *jsonrpc.Message) {
	hello, _ := ParseHello(first)
	waiting := map[string]*jsonrpc.Message{}
	for {
		m, err := c.Read()
		if err != nil {
			return
		}
		switch {
		case m.IsResponse():
			if orig := waiting[m.Key()]; orig != nil {
				r, _ := jsonrpc.NewResult(orig.ID, map[string]any{"answer": json.RawMessage(m.Result)})
				_ = c.Write(r)
			}
		case m.Method == "initialize":
			r, _ := jsonrpc.NewResult(m.ID, map[string]any{"server": hello.Server, "sub": p.Sub, "session": p.SessionID})
			_ = c.Write(r)
		case m.Method == "ask":
			req, _ := jsonrpc.NewRequest(json.RawMessage(`"e1"`), "elicitation/create", map[string]any{"message": "ok?"})
			waiting[`"e1"`] = m
			_ = c.Write(req)
		case m.Method == "notify":
			n, _ := jsonrpc.NewNotification("notifications/progress", map[string]any{"progress": 1})
			_ = c.Write(n)
			r, _ := jsonrpc.NewResult(m.ID, map[string]any{})
			_ = c.Write(r)
		case m.Method == "later":
			r, _ := jsonrpc.NewResult(m.ID, map[string]any{})
			_ = c.Write(r)
			n, _ := jsonrpc.NewNotification("notifications/tools/list_changed", nil)
			_ = c.Write(n)
		}
	}
}

func newTestServer(t *testing.T, mod func(*HTTPConfig)) (*httptest.Server, *HTTPHandler) {
	t.Helper()
	cfg := HTTPConfig{
		Resource:             "https://gw.example.com/mcp",
		AuthorizationServers: []string{"https://idp"},
		Scopes:               []string{"mcp"},
		AllowedOrigins:       []string{"https://app.example.com"},
		KnownServer:          func(n string) bool { return n == "fs" },
	}
	if mod != nil {
		mod(&cfg)
	}
	h, err := NewHTTPHandler(cfg, fakeAuth{}, echoServe)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	// Close sessions first: open SSE handlers only return when their
	// session ends, and srv.Close waits for them.
	t.Cleanup(func() { h.Close(); srv.Close() })
	return srv, h
}

type req struct {
	method, path, token, session, accept, origin string
	body                                         string
}

func do(t *testing.T, srv *httptest.Server, r req) *http.Response {
	t.Helper()
	if r.method == "" {
		r.method = http.MethodPost
	}
	if r.path == "" {
		r.path = "/mcp"
	}
	hr, err := http.NewRequest(r.method, srv.URL+r.path, strings.NewReader(r.body))
	if err != nil {
		t.Fatal(err)
	}
	if r.token != "" {
		hr.Header.Set("Authorization", "Bearer "+r.token)
	}
	if r.session != "" {
		hr.Header.Set("Mcp-Session-Id", r.session)
	}
	if r.origin != "" {
		hr.Header.Set("Origin", r.origin)
	}
	if r.method == http.MethodPost {
		hr.Header.Set("Content-Type", "application/json")
	}
	if r.accept == "" {
		r.accept = "application/json"
	}
	hr.Header.Set("Accept", r.accept)
	resp, err := srv.Client().Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

func initialize(t *testing.T, srv *httptest.Server, path, token string) string {
	t.Helper()
	resp := do(t, srv, req{path: path, token: token, body: initBody})
	body := readBody(t, resp)
	sid := resp.Header.Get("Mcp-Session-Id")
	if resp.StatusCode != 200 || sid == "" {
		t.Fatalf("initialize: %d %q %s", resp.StatusCode, sid, body)
	}
	return sid
}

// sseEvents reads data lines from an SSE body until it ends.
func sseEvents(t *testing.T, resp *http.Response, out chan<- *jsonrpc.Message) {
	t.Helper()
	defer close(out)
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
			m := &jsonrpc.Message{}
			if json.Unmarshal([]byte(data), m) == nil {
				out <- m
			}
		}
	}
}

func next(t *testing.T, ch <-chan *jsonrpc.Message) *jsonrpc.Message {
	t.Helper()
	select {
	case m, ok := <-ch:
		if !ok {
			t.Fatal("stream ended")
		}
		return m
	case <-time.After(3 * time.Second):
		t.Fatal("timeout")
	}
	return nil
}

func TestMetadata(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		resp := do(t, srv, req{method: http.MethodGet, path: path})
		var meta map[string]any
		if err := json.Unmarshal([]byte(readBody(t, resp)), &meta); err != nil {
			t.Fatal(err)
		}
		if meta["resource"] != "https://gw.example.com/mcp" || meta["authorization_servers"].([]any)[0] != "https://idp" {
			t.Fatalf("%s: %v", path, meta)
		}
	}
}

func TestAuthErrors(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	resp := do(t, srv, req{body: initBody})
	_ = readBody(t, resp)
	www := resp.Header.Get("WWW-Authenticate")
	if resp.StatusCode != 401 || !strings.Contains(www, `resource_metadata="https://gw.example.com/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatalf("no token: %d %q", resp.StatusCode, www)
	}
	resp = do(t, srv, req{token: "forged", body: initBody})
	_ = readBody(t, resp)
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("bad token: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	resp = do(t, srv, req{token: "noscope", body: initBody})
	_ = readBody(t, resp)
	if resp.StatusCode != 403 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="insufficient_scope"`) {
		t.Fatalf("scope: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
}

func TestRequestValidation(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	tests := []struct {
		name string
		r    req
		want int
	}{
		{"foreign origin", req{token: "alice", origin: "https://evil.example", body: initBody}, 403},
		{"allowed origin", req{token: "alice", origin: "https://app.example.com", body: initBody}, 200},
		{"unknown server", req{token: "alice", path: "/mcp/nope", body: initBody}, 404},
		{"nested path", req{token: "alice", path: "/mcp/fs/x", body: initBody}, 404},
		{"batch", req{token: "alice", body: "[" + initBody + "]"}, 400},
		{"garbage", req{token: "alice", body: "{"}, 400},
		{"no session", req{token: "alice", body: `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`}, 400},
		{"unknown session", req{token: "alice", session: "nope", body: `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`}, 404},
		{"put", req{method: http.MethodPut, token: "alice"}, 405},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := do(t, srv, tt.r)
			body := readBody(t, resp)
			if resp.StatusCode != tt.want {
				t.Fatalf("status %d, want %d: %s", resp.StatusCode, tt.want, body)
			}
		})
	}
}

func TestJSONRoundTrip(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	resp := do(t, srv, req{token: "alice", path: "/mcp/fs", body: initBody})
	body := readBody(t, resp)
	if !strings.Contains(body, `"server":"fs"`) || !strings.Contains(body, `"sub":"alice"`) {
		t.Fatalf("initialize body %s", body)
	}
	sid := resp.Header.Get("Mcp-Session-Id")
	if len(sid) != 32 || !strings.Contains(body, sid) {
		t.Fatalf("session id %q not the principal's (%s)", sid, body)
	}

	resp = do(t, srv, req{token: "alice", session: sid, body: `{"jsonrpc":"2.0","method":"notifications/initialized"}`})
	if _ = readBody(t, resp); resp.StatusCode != 202 {
		t.Fatalf("notification: %d", resp.StatusCode)
	}
	// Another principal cannot use the session.
	resp = do(t, srv, req{token: "bob", session: sid, body: `{"jsonrpc":"2.0","id":3,"method":"later"}`})
	if _ = readBody(t, resp); resp.StatusCode != 404 {
		t.Fatalf("hijack: %d", resp.StatusCode)
	}
}

func TestAggregatedEndpoint(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	resp := do(t, srv, req{token: "alice", body: initBody})
	if body := readBody(t, resp); !strings.Contains(body, `"server":"all"`) {
		t.Fatalf("body %s", body)
	}
}

func TestSSEWithServerRequest(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sid := initialize(t, srv, "/mcp", "alice")

	resp := do(t, srv, req{token: "alice", session: sid, accept: "application/json, text/event-stream",
		body: `{"jsonrpc":"2.0","id":2,"method":"ask"}`})
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("content type %q", resp.Header.Get("Content-Type"))
	}
	events := make(chan *jsonrpc.Message, 8)
	go sseEvents(t, resp, events)

	el := next(t, events)
	if el.Method != "elicitation/create" {
		t.Fatalf("want elicitation, got %+v", el)
	}
	answer := do(t, srv, req{token: "alice", session: sid, body: `{"jsonrpc":"2.0","id":"e1","result":{"action":"accept"}}`})
	if _ = readBody(t, answer); answer.StatusCode != 202 {
		t.Fatalf("answer: %d", answer.StatusCode)
	}
	final := next(t, events)
	if final.Key() != "2" || !strings.Contains(string(final.Result), "accept") {
		t.Fatalf("final %+v", final)
	}
	if _, ok := <-events; ok {
		t.Fatal("stream should end after the response")
	}
}

func TestSSENotificationBeforeResponse(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sid := initialize(t, srv, "/mcp", "alice")
	resp := do(t, srv, req{token: "alice", session: sid, accept: "text/event-stream", body: `{"jsonrpc":"2.0","id":2,"method":"notify"}`})
	events := make(chan *jsonrpc.Message, 8)
	go sseEvents(t, resp, events)
	if m := next(t, events); m.Method != "notifications/progress" {
		t.Fatalf("got %+v", m)
	}
	if m := next(t, events); m.Key() != "2" {
		t.Fatalf("got %+v", m)
	}
}

func TestGETStreamAndQueue(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sid := initialize(t, srv, "/mcp", "alice")
	// "later" sends a notification after its (JSON) response; no stream is
	// open, so it is queued until the GET stream opens.
	resp := do(t, srv, req{token: "alice", session: sid, body: `{"jsonrpc":"2.0","id":2,"method":"later"}`})
	_ = readBody(t, resp)

	get := do(t, srv, req{method: http.MethodGet, token: "alice", session: sid, accept: "text/event-stream"})
	events := make(chan *jsonrpc.Message, 8)
	go sseEvents(t, get, events)
	if m := next(t, events); m.Method != "notifications/tools/list_changed" {
		t.Fatalf("got %+v", m)
	}
	second := do(t, srv, req{method: http.MethodGet, token: "alice", session: sid, accept: "text/event-stream"})
	if _ = readBody(t, second); second.StatusCode != 409 {
		t.Fatalf("second GET: %d", second.StatusCode)
	}
}

func TestDelete(t *testing.T) {
	srv, h := newTestServer(t, nil)
	sid := initialize(t, srv, "/mcp", "alice")
	resp := do(t, srv, req{method: http.MethodDelete, token: "alice", session: sid})
	if _ = readBody(t, resp); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	resp = do(t, srv, req{token: "alice", session: sid, body: `{"jsonrpc":"2.0","id":2,"method":"later"}`})
	if _ = readBody(t, resp); resp.StatusCode != 404 {
		t.Fatalf("after delete: %d", resp.StatusCode)
	}
	h.mu.Lock()
	n := len(h.sessions)
	h.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d sessions left", n)
	}
}

func TestIdleSessionsReaped(t *testing.T) {
	srv, h := newTestServer(t, func(c *HTTPConfig) { c.SessionIdle = 50 * time.Millisecond })
	initialize(t, srv, "/mcp", "alice")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		n := len(h.sessions)
		h.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("idle session not reaped")
}

func TestSessionBoundToClientCert(t *testing.T) {
	p := principal.Principal{Sub: "alice", Issuer: "https://idp", Transport: principal.TransportHTTP,
		Cert: &principal.Cert{Subject: "CN=a", Thumbprint: "t1"}}
	s := &httpSession{p: p}
	if !s.ownedBy(p) {
		t.Fatal("owner refused")
	}
	other := p
	other.Cert = &principal.Cert{Subject: "CN=a", Thumbprint: "t2"}
	if s.ownedBy(other) {
		t.Error("session usable over another client certificate")
	}
	other.Cert = nil
	if s.ownedBy(other) {
		t.Error("session usable without the client certificate")
	}
}
