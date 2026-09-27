package transport

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
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

type sseEvent2 struct {
	id  string
	msg *jsonrpc.Message // nil for events without data (priming)
}

// sseWithIDs reads SSE events with their ids until the body ends.
func sseWithIDs(resp *http.Response, out chan<- sseEvent2) {
	defer close(out)
	sc := bufio.NewScanner(resp.Body)
	var ev sseEvent2
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "id: "):
			ev.id = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "data: "):
			m := &jsonrpc.Message{}
			if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), m) == nil {
				ev.msg = m
			}
		case line == "" && ev.id != "":
			out <- ev
			ev = sseEvent2{}
		}
	}
}

// diagnose, if set, describes the server state when nextEv times out.
var diagnose func() string

func nextEv(t *testing.T, ch <-chan sseEvent2) sseEvent2 {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("stream ended")
		}
		return ev
	case <-time.After(5 * time.Second):
		msg := "timeout"
		if diagnose != nil {
			msg += "\n" + diagnose()
		}
		buf := make([]byte, 1<<20)
		t.Fatalf("%s\ngoroutines:\n%s", msg, buf[:runtime.Stack(buf, true)])
	}
	return sseEvent2{}
}

// streamState describes the streams of all sessions of h.
func streamState(h *HTTPHandler) string {
	var b strings.Builder
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, s := range h.sessions {
		s.mu.Lock()
		fmt.Fprintf(&b, "session %s: pending=%d order=%d queue=%d\n", id, len(s.pending), len(s.order), len(s.queue))
		for num, st := range s.streams {
			fmt.Fprintf(&b, "  stream %d key=%q attached=%v conn=%d done=%v next=%d events=%d\n",
				num, st.key, st.attached, st.conn, st.done, st.next, len(st.events))
		}
		s.mu.Unlock()
	}
	return b.String()
}

func resume(t *testing.T, srv *httptest.Server, sid, lastID string) *http.Response {
	t.Helper()
	hr, _ := http.NewRequest(http.MethodGet, srv.URL+"/mcp", nil)
	hr.Header.Set("Authorization", "Bearer alice")
	hr.Header.Set("Mcp-Session-Id", sid)
	hr.Header.Set("Accept", "text/event-stream")
	hr.Header.Set("Last-Event-ID", lastID)
	// A new connection, as a client reconnecting after a drop.
	c := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := c.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// askAndDrop starts an "ask" request over SSE on its own TCP connection,
// reads the priming event and the elicitation, then closes the connection
// (an HTTP client may keep and drain a connection when a body is closed,
// which would not drop it). It returns the two events' ids.
func askAndDrop(t *testing.T, srv *httptest.Server, sid string) (priming, elicitation string) {
	t.Helper()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	body := `{"jsonrpc":"2.0","id":2,"method":"ask"}`
	fmt.Fprintf(conn, "POST /mcp HTTP/1.1\r\nHost: gw\r\nAuthorization: Bearer alice\r\nMcp-Session-Id: %s\r\n"+
		"Content-Type: application/json\r\nAccept: text/event-stream\r\nContent-Length: %d\r\n\r\n%s", sid, len(body), body)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan sseEvent2, 8)
	go sseWithIDs(resp, events)
	p := nextEv(t, events)
	if p.msg != nil {
		t.Fatalf("first event is not a priming event: %+v", p)
	}
	el := nextEv(t, events)
	if el.msg == nil || el.msg.Method != "elicitation/create" {
		t.Fatalf("want elicitation, got %+v", el)
	}
	return p.id, el.id
}

func answer(t *testing.T, srv *httptest.Server, sid string) {
	t.Helper()
	a := do(t, srv, req{token: "alice", session: sid, body: `{"jsonrpc":"2.0","id":"e1","result":{"action":"accept"}}`})
	if _ = readBody(t, a); a.StatusCode != 202 {
		t.Fatalf("answer: %d", a.StatusCode)
	}
}

func TestResumeRequestStream(t *testing.T) {
	srv, h := newTestServer(t, nil)
	diagnose = func() string { return streamState(h) }
	t.Cleanup(func() { diagnose = nil })
	sid := initialize(t, srv, "/mcp", "alice")
	_, elID := askAndDrop(t, srv, sid)
	// The response arrives while no connection is attached.
	answer(t, srv, sid)

	resp := resume(t, srv, sid, elID)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("resume: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	events := make(chan sseEvent2, 8)
	go sseWithIDs(resp, events)
	if p := nextEv(t, events); p.msg != nil || p.id != elID {
		t.Fatalf("priming %+v, want id %s", p, elID)
	}
	final := nextEv(t, events)
	if final.msg == nil || final.msg.Key() != "2" || !strings.Contains(string(final.msg.Result), "accept") {
		t.Fatalf("final %+v", final)
	}
	num, _, _ := parseEventID(elID)
	if n, _, _ := parseEventID(final.id); n != num {
		t.Fatalf("event %s is not on the resumed stream %d", final.id, num)
	}
	if _, ok := <-events; ok {
		t.Fatal("resumed stream should end after the response")
	}

	// Resuming it again after the response was delivered ends at once.
	again := resume(t, srv, sid, final.id)
	if body := readBody(t, again); again.StatusCode != 200 || strings.Contains(body, "data: {") {
		t.Fatalf("second resume: %d %q", again.StatusCode, body)
	}
}

func TestResumeReplaysMissedEvents(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sid := initialize(t, srv, "/mcp", "alice")
	primingID, _ := askAndDrop(t, srv, sid)
	answer(t, srv, sid)

	// From the priming id, the elicitation (possibly lost in transit) is
	// replayed before the response.
	resp := resume(t, srv, sid, primingID)
	events := make(chan sseEvent2, 8)
	go sseWithIDs(resp, events)
	nextEv(t, events) // priming
	if ev := nextEv(t, events); ev.msg == nil || ev.msg.Method != "elicitation/create" {
		t.Fatalf("replayed %+v", ev)
	}
	if ev := nextEv(t, events); ev.msg == nil || ev.msg.Key() != "2" {
		t.Fatalf("response %+v", ev)
	}
}

func TestResumeGETStream(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sid := initialize(t, srv, "/mcp", "alice")
	get := do(t, srv, req{method: http.MethodGet, token: "alice", session: sid, accept: "text/event-stream"})
	events := make(chan sseEvent2, 8)
	go sseWithIDs(get, events)
	nextEv(t, events) // priming
	later := func(id int) {
		r := do(t, srv, req{token: "alice", session: sid, body: fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"later"}`, id)})
		_ = readBody(t, r)
	}
	later(2)
	first := nextEv(t, events)
	if first.msg == nil || first.msg.Method != "notifications/tools/list_changed" || !strings.HasPrefix(first.id, "0-") {
		t.Fatalf("GET event %+v", first)
	}
	_ = get.Body.Close()
	// Wait until the server noticed the disconnect, then queue another.
	waitDetached(t, srv, sid)
	later(3)

	// Resuming from before the first event replays it, then delivers the
	// queued one.
	num, seq, _ := parseEventID(first.id)
	resp := resume(t, srv, sid, eventID(num, seq-1))
	ev2 := make(chan sseEvent2, 8)
	go sseWithIDs(resp, ev2)
	nextEv(t, ev2) // priming
	if ev := nextEv(t, ev2); ev.id != first.id {
		t.Fatalf("replay %+v, want %s", ev, first.id)
	}
	if ev := nextEv(t, ev2); ev.msg == nil || ev.msg.Method != "notifications/tools/list_changed" {
		t.Fatalf("queued %+v", ev)
	}
}

// waitDetached waits until the session's GET stream has no connection.
func waitDetached(t *testing.T, srv *httptest.Server, sid string) {
	t.Helper()
	h := srv.Config.Handler.(*HTTPHandler)
	for range 300 {
		h.mu.Lock()
		s := h.sessions[sid]
		h.mu.Unlock()
		s.mu.Lock()
		attached := s.streams[0] != nil && s.streams[0].attached
		s.mu.Unlock()
		if !attached {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("GET stream still attached")
}

func TestResumeErrors(t *testing.T) {
	srv, h := newTestServer(t, nil)
	sid := initialize(t, srv, "/mcp", "alice")
	for _, id := range []string{"junk", "7-1", "-1-2"} {
		if resp := resume(t, srv, sid, id); readBody(t, resp) == "" || resp.StatusCode != 400 {
			t.Errorf("Last-Event-ID %q: %d", id, resp.StatusCode)
		}
	}
	// Answered streams nobody resumed expire.
	_, elID := askAndDrop(t, srv, sid)
	answer(t, srv, sid)
	h.mu.Lock()
	s := h.sessions[sid]
	h.mu.Unlock()
	for range 300 {
		s.mu.Lock()
		num, _, _ := parseEventID(elID)
		done := s.streams[num] != nil && s.streams[num].done
		s.mu.Unlock()
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.expireStreams(time.Now().Add(resumeRetention + time.Minute))
	if resp := resume(t, srv, sid, elID); readBody(t, resp) == "" || resp.StatusCode != 400 {
		t.Fatalf("expired stream: %d", resp.StatusCode)
	}
}

func TestResumeReplacesStaleConnection(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	sid := initialize(t, srv, "/mcp", "alice")
	old := do(t, srv, req{method: http.MethodGet, token: "alice", session: sid, accept: "text/event-stream"})
	oldEvents := make(chan sseEvent2, 8)
	go sseWithIDs(old, oldEvents)
	priming := nextEv(t, oldEvents)

	// The client thinks the connection is gone and resumes; the server
	// has not noticed yet. The resumption takes over the stream.
	resp := resume(t, srv, sid, priming.id)
	if resp.StatusCode != 200 {
		t.Fatalf("resume: %d", resp.StatusCode)
	}
	events := make(chan sseEvent2, 8)
	go sseWithIDs(resp, events)
	nextEv(t, events) // priming
	select {
	case _, ok := <-oldEvents:
		if ok {
			t.Fatal("old connection got an event")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("old connection not ended")
	}
	r := do(t, srv, req{token: "alice", session: sid, body: `{"jsonrpc":"2.0","id":2,"method":"later"}`})
	_ = readBody(t, r)
	if ev := nextEv(t, events); ev.msg == nil || ev.msg.Method != "notifications/tools/list_changed" {
		t.Fatalf("event %+v", ev)
	}
}
