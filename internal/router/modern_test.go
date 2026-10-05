package router

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/signin"
)

// modernRouter is testRouter with the servers "modern" (MCP 2026-07-28),
// "modernnext" (only a later version) and "fragile" (a legacy server
// that exits on server/discover).
func modernRouter(t *testing.T) (*Router, *fakeLauncher) {
	t.Helper()
	r, l := testRouter(t, time.Hour)
	for _, name := range []string{"modern", "modernnext", "fragile"} {
		r.Backends[name] = &config.Backend{Name: name, Isolation: config.IsolationPrincipal}
	}
	return r, l
}

// A modern server gets no initialize: server/discover tells what it
// offers, and every request carries the gateway's per-request metadata.
// A legacy client does not notice.
func TestModernServer(t *testing.T) {
	r, l := modernRouter(t)
	c := connect(t, r, alice(), "modern", nil)

	got := names(t, c.roundTrip(1, "tools/list", map[string]any{}), "tools", "name")
	if strings.Join(got, ",") != "read_file,write_file,ask_roots" {
		t.Fatalf("tools = %v", got)
	}
	m := c.roundTrip(2, "tools/call", map[string]any{"name": "read_file"})
	if text, isErr := toolText(t, m); isErr || text != "modern did read_file" {
		t.Fatalf("call: %q %v", text, isErr)
	}
	if strings.Contains(string(m.Result), "resultType") {
		t.Errorf("resultType reached a legacy client: %s", m.Result)
	}

	fi := l.started("modern")[0]
	methods, metas, listens := fi.seen()
	if methods[0] != "server/discover" || strings.Contains(strings.Join(methods, " "), "initialize") {
		t.Fatalf("requests %v", methods)
	}
	for i, meta := range metas {
		var info struct{ Name string }
		_ = json.Unmarshal(meta[metaClientInfo], &info)
		if string(meta[metaProtocolVersion]) != `"2026-07-28"` || info.Name != "mcp-gateway" || string(meta[metaClientCapabilities]) != `{}` {
			t.Errorf("request %d (%s): _meta %v", i, methods[i], meta)
		}
	}
	// The stream for the list changes the server announces.
	if len(listens) != 1 || string(listens[0]) != `{"toolsListChanged":true}` {
		t.Fatalf("subscriptions/listen %s", listens)
	}

	// A change on the stream reaches the client, without the stream's id.
	n, _ := jsonrpc.NewNotification("notifications/tools/list_changed", map[string]any{
		"_meta": map[string]any{metaSubscriptionID: "listen-1"}})
	_ = fi.be.Write(n)
	if m := c.read(); m.Method != "notifications/tools/list_changed" || strings.Contains(string(m.Params), "subscriptionId") {
		t.Fatalf("notification %+v", m)
	}
}

// The log level travels with each request; resources/subscribe becomes
// the stream's resourceSubscriptions.
func TestModernServerLevelAndSubscriptions(t *testing.T) {
	r, l := modernRouter(t)
	c := connect(t, r, alice(), "modern", nil)
	// Without a level, none is sent and the server logs nothing.
	if text, _ := toolText(t, c.roundTrip(1, "tools/call", map[string]any{"name": "read_log"})); text != "log level " {
		t.Fatalf("call: %q", text)
	}
	if m := c.roundTrip(2, "logging/setLevel", map[string]any{"level": "info"}); m.Error != nil {
		t.Fatalf("setLevel: %+v", m.Error)
	}
	c.send(3, "tools/call", map[string]any{"name": "read_log"})
	if m := c.read(); m.Method != "notifications/message" {
		t.Fatalf("want the log message first, got %+v", m)
	}
	if text, _ := toolText(t, c.read()); text != `log level "info"` {
		t.Fatalf("call: %q", text)
	}

	if m := c.roundTrip(4, "resources/subscribe", map[string]any{"uri": "file:///ok/a.txt"}); m.Error != nil {
		t.Fatalf("subscribe: %+v", m.Error)
	}
	fi := l.started("modern")[0]
	// The new stream is written before the answer, but the server reads
	// it on its own time.
	deadline := time.Now().Add(2 * time.Second)
	methods, _, listens := fi.seen()
	for len(listens) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		methods, _, listens = fi.seen()
	}
	if strings.Contains(strings.Join(methods, " "), "logging/setLevel") || strings.Contains(strings.Join(methods, " "), "resources/subscribe") {
		t.Errorf("legacy methods reached the modern server: %v", methods)
	}
	if len(listens) != 2 || !strings.Contains(string(listens[1]), `"resourceSubscriptions":["file:///ok/a.txt"]`) {
		t.Fatalf("subscriptions/listen %s", listens)
	}
	select {
	case id := <-fi.cancelled:
		if !strings.Contains(id, "listen-") {
			t.Fatalf("cancelled %s", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the previous stream was not cancelled")
	}
}

// An interim result asking the client for input is not passed on yet.
func TestModernServerInputRequired(t *testing.T) {
	r, _ := modernRouter(t)
	c := connect(t, r, alice(), "modern", nil)
	m := c.roundTrip(1, "tools/call", map[string]any{"name": "ask_input"})
	if m.Error == nil || !strings.Contains(m.Error.Message, "does not pass on yet") {
		t.Fatalf("got %+v", m)
	}
}

// A modern server without the gateway's version does not start, with an
// error naming the versions it speaks (the agent sees "backend
// unavailable", the log says why).
func TestModernServerOtherVersion(t *testing.T) {
	r, _ := modernRouter(t)
	r.init()
	_, _, err := r.pool.acquire(context.Background(), r.Backends["modernnext"], alice())
	if err == nil || !strings.Contains(err.Error(), "speaks MCP 2027-03-01") {
		t.Fatalf("got %v", err)
	}
}

// A legacy server that exits on server/discover is started again and
// initialized, and its definition is not probed again.
func TestFragileLegacyServer(t *testing.T) {
	r, l := modernRouter(t)
	c := connect(t, r, alice(), "fragile", nil)
	if text, isErr := toolText(t, c.roundTrip(1, "tools/call", map[string]any{"name": "read_file"})); isErr || text != "fragile did read_file" {
		t.Fatalf("call: %q %v", text, isErr)
	}
	inst := l.started("fragile")
	if len(inst) != 2 {
		t.Fatalf("%d instances started", len(inst))
	}
	if methods, _, _ := inst[1].seen(); methods[0] != "initialize" {
		t.Fatalf("second instance got %v", methods)
	}
}

// The era of a definition is probed once: later instances of a legacy
// server go straight to initialize.
func TestEraRemembered(t *testing.T) {
	r, l := modernRouter(t)
	for i, p := range []string{"alice", "bob"} {
		pr := alice()
		if p == "bob" {
			pr = bob()
		}
		c := connect(t, r, pr, "fs", nil)
		if text, _ := toolText(t, c.roundTrip(1, "tools/call", map[string]any{"name": "read_file"})); text != "fs did read_file" {
			t.Fatalf("%s: %q", p, text)
		}
		methods, _, _ := l.started("fs")[i].seen()
		want := map[int]string{0: "server/discover", 1: "initialize"}[i]
		if methods[0] != want {
			t.Fatalf("%s's instance began with %v", p, methods)
		}
	}
}

func TestWithMeta(t *testing.T) {
	raw, err := withMeta(map[string]json.RawMessage{
		"name":  json.RawMessage(`"x"`),
		"_meta": json.RawMessage(`{"progressToken":"p1","io.modelcontextprotocol/clientCapabilities":{"sampling":{}}}`),
	}, map[string]any{metaProtocolVersion: modernVersion})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); got != `{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","progressToken":"p1"},"name":"x"}` {
		t.Fatalf("got %s", got)
	}
	if raw, _ := withMeta(nil, map[string]any{"k": 1}); string(raw) != `{"_meta":{"k":1}}` {
		t.Fatalf("nil params: %s", raw)
	}
	if _, err := withMeta(json.RawMessage(`[1]`), nil); err == nil {
		t.Fatal("array params accepted")
	}
}

func TestCompleteResult(t *testing.T) {
	if raw, ir := completeResult(json.RawMessage(`{"resultType":"complete","content":[]}`)); ir || string(raw) != `{"content":[]}` {
		t.Fatalf("complete: %s %v", raw, ir)
	}
	if _, ir := completeResult(json.RawMessage(`{"resultType":"input_required"}`)); !ir {
		t.Fatal("input_required not reported")
	}
	if raw, ir := completeResult(json.RawMessage(`{"content":[]}`)); ir || string(raw) != `{"content":[]}` {
		t.Fatalf("legacy: %s", raw)
	}
}

// A legacy server that never answers server/discover is initialized after
// the probe's timeout, and the unanswered probe does not keep the
// instance busy.
func TestSilentProbe(t *testing.T) {
	r, l := modernRouter(t)
	r.Backends["silent"] = &config.Backend{Name: "silent", Isolation: config.IsolationPrincipal}
	r.init()
	defer func(d time.Duration) { probeTimeout = d }(probeTimeout)
	probeTimeout = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	u, release, err := r.pool.acquire(ctx, r.Backends["silent"], alice())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if u.modern || u.busy() {
		t.Fatalf("modern %v, busy %v", u.modern, u.busy())
	}
	if methods, _, _ := l.started("silent")[0].seen(); len(methods) != 2 || methods[1] != "initialize" {
		t.Fatalf("requests %v", methods)
	}
}

// A probe that fails for a reason other than the server's era (a refused
// token, an HTTP 503 the connector reports) does not make the server
// legacy: the next start probes again. A refused token stays the
// sign-in's error.
func TestProbeFailureNotRemembered(t *testing.T) {
	r, _ := modernRouter(t)
	for _, name := range []string{"refused", "unavailable"} {
		r.Backends[name] = &config.Backend{Name: name, Isolation: config.IsolationPrincipal}
	}
	r.init()
	ctx := context.Background()
	_, _, err := r.pool.acquire(ctx, r.Backends["refused"], alice())
	if err == nil || !strings.Contains(err.Error(), signin.RejectedMarker) || strings.Contains(err.Error(), "initializing") {
		t.Fatalf("refused: %v", err)
	}
	if _, _, err := r.pool.acquire(ctx, r.Backends["unavailable"], alice()); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("unavailable: %v", err)
	}
	for _, name := range []string{"refused", "unavailable"} {
		if e := r.pool.era(r.Backends[name]); e != eraUnknown {
			t.Errorf("%s: era %v remembered", name, e)
		}
	}
}
