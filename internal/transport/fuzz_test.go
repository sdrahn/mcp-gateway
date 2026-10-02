package transport

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// recordingServe answers every request at once and records, per session
// owner, the messages that reached a session.
type recordingServe struct {
	mu       sync.Mutex
	sessions int
	got      map[string]int // principal sub to messages received
}

func (rs *recordingServe) serve(_ context.Context, c jsonrpc.MessageConn, p principal.Principal, _ *jsonrpc.Message) {
	rs.mu.Lock()
	rs.sessions++
	rs.mu.Unlock()
	for {
		m, err := c.Read()
		if err != nil {
			return
		}
		rs.mu.Lock()
		rs.got[p.Sub]++
		rs.mu.Unlock()
		if m.IsRequest() {
			r, _ := jsonrpc.NewResult(m.ID, map[string]any{})
			_ = c.Write(r)
		}
	}
}

func (rs *recordingServe) snapshot() (int, map[string]int) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	got := map[string]int{}
	for k, v := range rs.got {
		got[k] = v
	}
	return rs.sessions, got
}

var (
	fuzzMethods = []string{http.MethodPost, http.MethodGet, http.MethodDelete, http.MethodPut, "PATCH", "OPTIONS"}
	fuzzAccepts = []string{"application/json", "application/json, text/event-stream", "text/event-stream", "", "*/*"}
)

// FuzzHTTPHandler sends one request of any shape to a handler with a
// session of alice and one of bob. Without a valid token no session
// receives anything and none is created; with one, the request never
// reaches the other principal's session; no request causes a 5xx.
func FuzzHTTPHandler(f *testing.F) {
	f.Add(uint8(0), "/mcp", "alice", uint8(1), "", uint8(0), "", "application/json", []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	f.Add(uint8(0), "/mcp", "bob", uint8(1), "", uint8(0), "", "application/json", []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	f.Add(uint8(0), "/mcp/fs", "", uint8(0), "", uint8(0), "", "application/json", []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	f.Add(uint8(0), "/mcp", "carol", uint8(0), "", uint8(0), "", "application/json", []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	f.Add(uint8(1), "/mcp", "alice", uint8(2), "", uint8(2), "", "", []byte{})
	f.Add(uint8(2), "/mcp", "bob", uint8(1), "", uint8(0), "", "", []byte{})
	f.Add(uint8(0), "/mcp", "alice", uint8(1), "", uint8(0), "https://evil.example", "application/json", []byte(`{"jsonrpc":"2.0","method":"notifications/x"}`))
	f.Add(uint8(0), "/mcp", "alice", uint8(3), "x", uint8(0), "", "application/json", []byte(`[{"jsonrpc":"2.0","id":1,"method":"a"}]`))
	f.Add(uint8(0), "/.well-known/oauth-protected-resource/mcp", "", uint8(0), "", uint8(0), "", "", []byte{})

	f.Fuzz(func(t *testing.T, method uint8, path, token string, sessionChoice uint8, sessionID string, accept uint8, origin, contentType string, body []byte) {
		rs := &recordingServe{got: map[string]int{}}
		h, err := NewHTTPHandler(HTTPConfig{
			Resource:             "https://gw.example.com/mcp",
			AuthorizationServers: []string{"https://idp"},
			Scopes:               []string{"mcp"},
			AllowedOrigins:       []string{"https://app.example.com"},
			KnownServer:          func(n string) bool { return n == "fs" },
		}, fakeAuth{}, rs.serve)
		if err != nil {
			t.Fatal(err)
		}
		defer h.Close()
		sid := map[string]string{}
		for _, who := range []string{"alice", "bob"} {
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader([]byte(initBody)))
			r.Header.Set("Authorization", "Bearer "+who)
			r.Header.Set("Content-Type", "application/json")
			h.ServeHTTP(rec, r)
			if sid[who] = rec.Header().Get(sessionHeader); rec.Code != 200 || sid[who] == "" {
				t.Fatalf("initialize %s: %d", who, rec.Code)
			}
		}
		// Wait for both sessions to have taken their initialize.
		deadline := time.Now().Add(5 * time.Second)
		for {
			n, got := rs.snapshot()
			if n == 2 && got["alice"] == 1 && got["bob"] == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("sessions not ready: %d %v", n, got)
			}
			time.Sleep(time.Millisecond)
		}

		r, err := http.NewRequest(fuzzMethods[int(method)%len(fuzzMethods)], "http://gw.example.com/", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.URL.Path = path
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		switch sessionChoice % 4 {
		case 1:
			r.Header.Set(sessionHeader, sid["alice"])
		case 2:
			r.Header.Set(sessionHeader, sid["bob"])
		case 3:
			r.Header.Set(sessionHeader, sessionID)
		}
		if a := fuzzAccepts[int(accept)%len(fuzzAccepts)]; a != "" {
			r.Header.Set("Accept", a)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		// Streams last as long as the client stays: end them soon.
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r.WithContext(ctx))

		if rec.Code >= 500 {
			t.Errorf("status %d", rec.Code)
		}
		time.Sleep(time.Millisecond) // let a pushed message arrive
		n, got := rs.snapshot()
		valid := token == "alice" || token == "bob"
		if !valid {
			if n != 2 || got["alice"] != 1 || got["bob"] != 1 {
				t.Errorf("token %q reached a session: %d sessions, %v", token, n, got)
			}
			return
		}
		other := map[string]string{"alice": "bob", "bob": "alice"}[token]
		if got[other] != 1 {
			t.Errorf("%s reached %s's session: %v", token, other, got)
		}
	})
}
