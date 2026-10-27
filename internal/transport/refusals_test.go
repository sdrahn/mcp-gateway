package transport

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a bytes.Buffer for a logger that handlers write to
// concurrently.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

// records returns the logged records with the message msg.
func (b *syncBuffer) records(t *testing.T, msg string) []map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.b.String()), "\n") {
		var rec map[string]any
		if line == "" {
			continue
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// Each refusal is logged with its status, why, and from where: a client
// that gets a 4xx is never left without a word in the journal.
func TestRefusalsLogged(t *testing.T) {
	logs := &syncBuffer{}
	srv, _ := newTestServer(t, func(c *HTTPConfig) {
		c.Log = slog.New(slog.NewJSONHandler(logs, nil))
	})
	tests := []struct {
		name   string
		r      req
		status int
		reason string
		attr   string // a further attribute's key=value
	}{
		{"unknown server", req{token: "alice", path: "/mcp/nope", body: initBody}, 404, "no such endpoint", ""},
		{"foreign origin", req{token: "alice", origin: "https://evil.example", body: initBody}, 403, "origin not in http.allowed_origins", "origin=https://evil.example"},
		{"no token", req{body: initBody}, 401, "no bearer token", ""},
		{"scope", req{token: "noscope", body: initBody}, 403, "token lacks a scope of http.scopes", "err=insufficient scope"},
		{"batch", req{token: "alice", body: "[" + initBody + "]"}, 400, "JSON-RPC batch", "sub=alice"},
		{"garbage", req{token: "alice", body: "{"}, 400, "body not JSON", ""},
		{"no session", req{token: "alice", body: `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`}, 400, "no session", "rpc_method=tools/list"},
		{"unknown session", req{token: "alice", session: "nope", body: `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`}, 404, "unknown session", "sub=alice"},
		{"put", req{method: http.MethodPut, token: "alice"}, 405, "method not allowed", ""},
		{"get", req{method: http.MethodGet, token: "alice"}, 405, "GET without Accept", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := len(logs.records(t, "HTTP request refused"))
			resp := do(t, srv, tt.r)
			_ = readBody(t, resp)
			if resp.StatusCode != tt.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tt.status)
			}
			recs := logs.records(t, "HTTP request refused")
			if len(recs) != before+1 {
				t.Fatalf("%d records logged, want 1", len(recs)-before)
			}
			rec := recs[len(recs)-1]
			reason, _ := rec["reason"].(string)
			if !strings.HasPrefix(reason, tt.reason) || rec["status"] != float64(tt.status) || rec["remote"] == "" || rec["path"] == nil {
				t.Errorf("logged %v", rec)
			}
			if k, v, ok := strings.Cut(tt.attr, "="); ok {
				if got, _ := rec[k].(string); !strings.Contains(got, v) {
					t.Errorf("%s: %q, want %q", k, got, v)
				}
			}
		})
	}
}

// Per reason, refusalBurst in a window are logged; the next one logged
// counts the ones left out. Other reasons are not held back.
func TestRefusalRateLimit(t *testing.T) {
	now := time.Unix(1000, 0)
	l := refusalLimiter{now: func() time.Time { return now }}
	for i := 0; i < refusalBurst; i++ {
		if ok, n := l.allow("no bearer token"); !ok || n != 0 {
			t.Fatalf("refusal %d: %v %d", i, ok, n)
		}
	}
	for i := 0; i < 3; i++ {
		if ok, _ := l.allow("no bearer token"); ok {
			t.Fatalf("refusal %d past the burst logged", refusalBurst+i)
		}
	}
	if ok, _ := l.allow("unknown session"); !ok {
		t.Fatal("another reason held back")
	}
	now = now.Add(refusalWindow)
	if ok, n := l.allow("no bearer token"); !ok || n != 3 {
		t.Fatalf("next window: %v, %d left out, want 3", ok, n)
	}
	if ok, n := l.allow("no bearer token"); !ok || n != 0 {
		t.Fatalf("then: %v %d", ok, n)
	}
}
