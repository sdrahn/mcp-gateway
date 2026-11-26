package router

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
)

func withKey(name, key string, args map[string]any) map[string]any {
	p := map[string]any{"name": name, "_meta": map[string]any{IdempotencyMeta: key, "progressToken": "p-1"}}
	if args != nil {
		p["arguments"] = args
	}
	return p
}

func toolCalls(f *fakeInstance) int {
	methods, _, _ := f.seen()
	n := 0
	for _, m := range methods {
		if m == "tools/call" {
			n++
		}
	}
	return n
}

// A call sent again with its key is answered from the first: the server
// runs it once; without a key, every call runs. The key never reaches the
// server; the audit names it, and records the repeat as such.
func TestIdempotentRepeat(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	logs := &syncWriter{w: &strings.Builder{}}
	r.Audit = audit.New(logs)
	c := connect(t, r, alice(), "fs", nil)

	for i := range 3 {
		if text, _ := toolText(t, c.roundTrip(1+i, "tools/call", withKey("read_counter", "k-1", nil))); text != "fs count 1" {
			t.Fatalf("call %d: %q", i, text)
		}
	}
	f := l.started("fs")[0]
	if n := toolCalls(f); n != 1 {
		t.Fatalf("the server ran %d calls", n)
	}
	if text, _ := toolText(t, c.roundTrip(5, "tools/call", map[string]any{"name": "read_counter"})); text != "fs count 2" {
		t.Fatalf("without a key: %q", text)
	}
	_, metas, _ := f.seen()
	for _, m := range metas {
		if _, ok := m[IdempotencyMeta]; ok {
			t.Fatalf("the server saw the key: %v", m)
		}
	}
	if string(metas[len(metas)-2]["progressToken"]) == "" {
		t.Fatalf("the rest of _meta went missing: %v", metas)
	}
	id := decisionIDOf(t, logs, "read_counter")
	out := logs.String()
	if !strings.Contains(out, `"idempotency_key":"k-1"`) {
		t.Fatalf("decision without the key:\n%s", out)
	}
	repeats := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, `"event":"mcp-repeat"`) {
			repeats++
			if !strings.Contains(line, `"outcome":"answered"`) || !strings.Contains(line, `"idempotency_key":"k-1"`) {
				t.Fatalf("repeat record: %s", line)
			}
		}
	}
	if repeats != 2 || !strings.Contains(out, `"decision_id":"`) || id == "" {
		t.Fatalf("%d repeat records:\n%s", repeats, out)
	}
	if strings.Count(out, `"event":"mcp-result"`) != 2 {
		t.Fatalf("results: want one per run (two):\n%s", out)
	}
}

// The same key for another call is refused, and nothing runs.
func TestIdempotentOtherCallRefused(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	c := connect(t, r, alice(), "fs", nil)
	if text, _ := toolText(t, c.roundTrip(1, "tools/call", withKey("read_counter", "k-2", map[string]any{"a": 1}))); text != "fs count 1" {
		t.Fatalf("first: %q", text)
	}
	for i, p := range []map[string]any{
		withKey("read_counter", "k-2", map[string]any{"a": 2}),
		withKey("read_counter", "k-2", nil),
		withKey("read_file", "k-2", map[string]any{"a": 1}),
	} {
		m := c.roundTrip(2+i, "tools/call", p)
		if m.Error == nil || m.Error.Code != jsonrpc.CodeInvalidParams || !strings.Contains(m.Error.Message, "was used for another call") {
			t.Fatalf("%v: %+v", p, m)
		}
	}
	if n := toolCalls(l.started("fs")[0]); n != 1 {
		t.Fatalf("the server ran %d calls", n)
	}
	// Map order does not make another call.
	if text, _ := toolText(t, c.roundTrip(9, "tools/call", withKey("read_counter", "k-3", map[string]any{"a": 1, "b": 2}))); text != "fs count 2" {
		t.Fatalf("k-3: %q", text)
	}
	if text, _ := toolText(t, c.roundTrip(10, "tools/call", withKey("read_counter", "k-3", map[string]any{"b": 2, "a": 1}))); text != "fs count 2" {
		t.Fatalf("k-3 again: %q", text)
	}
}

// A call with a key runs on when its client goes away; the call sent
// again with the key, in another session, waits for it and gets its
// result: the server ran it once and was never told to cancel it.
func TestIdempotentRunsOn(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	c1 := connect(t, r, alice(), "fs", nil)
	c1.send(1, "tools/call", withKey("commit", "k-4", nil))
	var f *fakeInstance
	deadline := time.Now().Add(2 * time.Second)
	for f == nil || toolCalls(f) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the call did not reach the server")
		}
		if s := l.started("fs"); len(s) > 0 {
			f = s[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	c1.close() // the connection is cut while the call runs

	c2 := connect(t, r, alice(), "fs", nil)
	c2.send(2, "tools/call", withKey("commit", "k-4", nil))
	select {
	case m := <-c2.msgs:
		t.Fatalf("answered while the first runs: %+v", m)
	case <-time.After(100 * time.Millisecond):
	}
	close(f.commit)
	m := c2.read()
	if text, _ := toolText(t, m); text != "committed" {
		t.Fatalf("repeat: %+v", m)
	}
	if n := toolCalls(f); n != 1 {
		t.Fatalf("the server ran %d calls", n)
	}
	select {
	case id := <-f.cancelled:
		t.Fatalf("the server was told to cancel %s", id)
	default:
	}
}

// A key must be a short string of printable ASCII.
func TestIdempotencyKeyChecked(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	c := connect(t, r, alice(), "fs", nil)
	for i, key := range []any{"", "a b", strings.Repeat("x", maxIdempotencyKey+1), 7, "ä"} {
		p := map[string]any{"name": "read_counter", "_meta": map[string]any{IdempotencyMeta: key}}
		m := c.roundTrip(1+i, "tools/call", p)
		if m.Error == nil || m.Error.Code != jsonrpc.CodeInvalidParams || !strings.Contains(m.Error.Message, IdempotencyMeta) {
			t.Fatalf("key %v: %+v", key, m)
		}
	}
	if s := l.started("fs"); len(s) > 0 && toolCalls(s[0]) > 0 {
		t.Fatal("a call with a bad key ran")
	}
	// A key of the longest length passes.
	long := strings.Repeat("y", maxIdempotencyKey)
	if text, _ := toolText(t, c.roundTrip(9, "tools/call", withKey("read_counter", long, nil))); text != "fs count 1" {
		t.Fatalf("longest key: %q", text)
	}
}

// Keys are per principal: bob's call with alice's key is a call of its own.
func TestIdempotencyPerPrincipal(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	a := connect(t, r, alice(), "fs", nil)
	bob := alice()
	bob.Sub = "bob"
	b := connect(t, r, bob, "fs", nil)
	if text, _ := toolText(t, a.roundTrip(1, "tools/call", withKey("read_counter", "k-5", nil))); text != "fs count 1" {
		t.Fatalf("alice: %q", text)
	}
	if text, _ := toolText(t, b.roundTrip(1, "tools/call", withKey("read_counter", "k-5", nil))); text != "fs count 1" {
		t.Fatalf("bob: %q", text)
	}
	if n := len(l.started("fs")); n != 2 {
		t.Fatalf("%d instances", n)
	}
}

// The store: an outcome expires after the window; keep false forgets it
// at once; a principal's keys are bounded.
func TestIdemStore(t *testing.T) {
	var st idemStore
	p := alice()
	e, first, err := st.begin(p, "k", "fp", "fs", "x")
	if !first || err != nil {
		t.Fatal(first, err)
	}
	if e2, first, _ := st.begin(p, "k", "fp", "fs", "x"); first || e2 != e {
		t.Fatal("not kept")
	}
	st.finish(e, nil, true, 20*time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	if _, first, _ := st.begin(p, "k", "fp", "fs", "x"); !first {
		t.Fatal("not expired")
	}
	e3, _, _ := st.begin(p, "n", "fp", "fs", "x")
	st.finish(e3, nil, false, time.Hour)
	if _, first, _ := st.begin(p, "n", "fp", "fs", "x"); !first {
		t.Fatal("kept without an outcome")
	}
	for i := 0; i < maxIdempotencyKeys; i++ {
		if _, _, err := st.begin(p, "many-"+itoa(i), "fp", "fs", "x"); err != nil {
			if i < maxIdempotencyKeys-3 {
				t.Fatalf("key %d refused: %v", i, err)
			}
			if !strings.Contains(err.Message, "kept for you already") {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("no bound")
}

func TestTakeIdempotencyKey(t *testing.T) {
	params := map[string]json.RawMessage{"_meta": json.RawMessage(`{"` + IdempotencyMeta + `":"k"}`)}
	if k, err := takeIdempotencyKey(params); k != "k" || err != nil {
		t.Fatal(k, err)
	}
	if _, ok := params["_meta"]; ok {
		t.Fatalf("an emptied _meta stays: %s", params["_meta"])
	}
}

// A call sent again while its approval is pending waits for that
// approval: no second approval is asked for, and the call runs once.
func TestIdempotentPendingApproval(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	c1 := connect(t, r, alice(), "fs", map[string]any{"elicitation": map[string]any{}})
	c1.send(1, "tools/call", withKey("write_file", "k-6", nil))
	el := readSkipProgress(c1)
	if el.Method != "elicitation/create" {
		t.Fatalf("want elicitation, got %+v", el)
	}
	c2 := connect(t, r, alice(), "fs", map[string]any{"elicitation": map[string]any{}})
	c2.send(2, "tools/call", withKey("write_file", "k-6", nil))
	select {
	case m := <-c2.msgs:
		t.Fatalf("the repeat got %+v", m) // no second approval, no answer yet
	case <-time.After(100 * time.Millisecond):
	}
	c1.write(result(t, el.ID, map[string]any{"action": "accept", "content": map[string]any{"scope": "once"}}))
	for _, c := range []*client{c1, c2} {
		if text, isErr := toolText(t, readSkipProgress(c)); isErr || text != "fs did write_file" {
			t.Fatalf("got %q %v", text, isErr)
		}
	}
	if n := toolCalls(l.started("fs")[0]); n != 1 {
		t.Fatalf("the server ran %d calls", n)
	}
}

// readSkipProgress reads c's next message that is not a progress
// notification.
func readSkipProgress(c *client) *jsonrpc.Message {
	for {
		if m := c.read(); m.Method != "notifications/progress" {
			return m
		}
	}
}

// A client's cancellation does not end a call with a key: the server is
// not told, the call ends, and a repeat gets its result.
func TestIdempotentIgnoresCancel(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	c := connect(t, r, alice(), "fs", nil)
	c.send(1, "tools/call", withKey("commit", "k-7", nil))
	var f *fakeInstance
	deadline := time.Now().Add(2 * time.Second)
	for f == nil || toolCalls(f) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the call did not reach the server")
		}
		if s := l.started("fs"); len(s) > 0 {
			f = s[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	n, _ := jsonrpc.NewNotification("notifications/cancelled", map[string]any{"requestId": 1})
	c.write(n)
	select {
	case id := <-f.cancelled:
		t.Fatalf("the server was told to cancel %s", id)
	case <-time.After(100 * time.Millisecond):
	}
	close(f.commit)
	if text, _ := toolText(t, c.roundTrip(2, "tools/call", withKey("commit", "k-7", nil))); text != "committed" {
		t.Fatalf("repeat: %q", text)
	}
	if n := toolCalls(f); n != 1 {
		t.Fatalf("the server ran %d calls", n)
	}
}

// An agent of MCP 2026-07-28, without a session: its call with a key runs
// once, alongside the protocol's own _meta.
func TestIdempotentModernAgent(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	c := agent(t, r, alice(), "fs")
	for i := range 2 {
		m := c.roundTrip(1+i, "tools/call", withAgentMeta(map[string]any{"name": "read_counter"}, map[string]any{IdempotencyMeta: "k-8"}))
		if text, _ := toolText(t, m); text != "fs count 1" {
			t.Fatalf("call %d: %+v", i, m)
		}
	}
	if n := toolCalls(l.started("fs")[0]); n != 1 {
		t.Fatalf("the server ran %d calls", n)
	}
}
