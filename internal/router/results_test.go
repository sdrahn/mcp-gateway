package router

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
)

func TestCallOutcome(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancel2 := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel2()
	bg := context.Background()
	for _, tc := range []struct {
		name          string
		ctx           context.Context
		raw           string
		rerr          *jsonrpc.Error
		sendErr       error
		outcome, text string
	}{
		{"ok", bg, `{"content":[{"type":"text","text":"fine"}]}`, nil, nil, "ok", ""},
		{"not JSON", bg, `nonsense`, nil, nil, "ok", ""},
		{"tool error", bg, `{"isError":true,"content":[{"type":"image"},{"type":"text","text":"zypper\n exited 4"}]}`, nil, nil, "tool_error", "zypper exited 4"},
		{"tool error without text", bg, `{"isError":true,"content":[]}`, nil, nil, "tool_error", ""},
		{"rpc error", bg, ``, &jsonrpc.Error{Code: -32603, Message: "backend broke"}, nil, "error", "backend broke"},
		{"unreachable", bg, ``, &jsonrpc.Error{Code: -32603, Message: "x"}, errors.New("connection closed"), "error", "x"},
		{"send error only", bg, ``, nil, errors.New("connection closed"), "error", "connection closed"},
		{"cancelled", cancelled, ``, &jsonrpc.Error{Message: "x"}, context.Canceled, "cancelled", ""},
		{"cancelled context", cancelled, ``, &jsonrpc.Error{Message: "x"}, nil, "cancelled", ""},
		{"timeout", expired, ``, &jsonrpc.Error{Message: "x"}, context.DeadlineExceeded, "timeout", ""},
	} {
		outcome, text := callOutcome(tc.ctx, json.RawMessage(tc.raw), tc.rerr, tc.sendErr)
		if outcome != tc.outcome || text != tc.text {
			t.Errorf("%s: %q %q, want %q %q", tc.name, outcome, text, tc.outcome, tc.text)
		}
	}
}

func TestShortText(t *testing.T) {
	if got := shortText("a\n\tb  c"); got != "a b c" {
		t.Fatalf("one line: %q", got)
	}
	long := strings.Repeat("ä", maxResultError) // two bytes each
	got := shortText(long)
	if !strings.HasSuffix(got, "…") || len(got) > maxResultError+len("…") || !strings.HasPrefix(long, strings.TrimSuffix(got, "…")) {
		t.Fatalf("cut: %d bytes %q", len(got), got)
	}
	if tokenText(json.RawMessage(`"custos:e-1/call_3"`)) != "custos:e-1/call_3" || tokenText(json.RawMessage(`17`)) != "17" {
		t.Fatal("tokenText")
	}
}

// resultRecords are the mcp-result audit records in logs.
func resultRecords(t *testing.T, logs *syncWriter) []map[string]any {
	t.Helper()
	logs.mu.Lock()
	defer logs.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(logs.w.String(), "\n") {
		if !strings.Contains(line, `"event":"mcp-result"`) {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		out = append(out, rec)
	}
	return out
}

// waitResult waits for the mcp-result record of tool name.
func waitResult(t *testing.T, logs *syncWriter, name string) map[string]any {
	t.Helper()
	for i := 0; i < 400; i++ {
		for _, rec := range resultRecords(t, logs) {
			if rec["name"] == name {
				return rec
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no mcp-result record for %s: %s", name, logs.String())
	return nil
}

// decisionID is the decision_id of tool name's decision record.
func decisionIDOf(t *testing.T, logs *syncWriter, name string) string {
	t.Helper()
	logs.mu.Lock()
	defer logs.mu.Unlock()
	for _, line := range strings.Split(logs.w.String(), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil && rec["msg"] == "mcp" && rec["event"] == nil && rec["name"] == name {
			id, _ := rec["decision_id"].(string)
			return id
		}
	}
	return ""
}

// Each forwarded tool call is audited with its outcome (mcp-result): ok,
// a tool error, a JSON-RPC error, the server dying, a call cancelled; the
// error text only with the obligation audit "full", bounded; the
// decision id and the client's progress token.
func TestResultRecords(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	logs := &syncWriter{w: &strings.Builder{}}
	r.Audit = audit.New(logs)
	p := alice()
	c := connect(t, r, p, "fs", nil)

	c.roundTrip(1, "tools/call", map[string]any{"name": "read_file", "_meta": map[string]any{"progressToken": "custos:e-1/call_3"}})
	rec := waitResult(t, logs, "read_file")
	if rec["outcome"] != "ok" || rec["sub"] != "alice" || rec["server"] != "fs" || rec["session"] != p.SessionID ||
		rec["progress_token"] != "custos:e-1/call_3" || rec["error"] != nil || rec["audit"] != true {
		t.Fatalf("ok: %+v", rec)
	}
	if _, ok := rec["duration_ms"].(float64); !ok {
		t.Fatalf("no duration: %+v", rec)
	}
	if id := decisionIDOf(t, logs, "read_file"); id == "" || rec["decision_id"] != id {
		t.Fatalf("decision id %v, the decision's %q", rec["decision_id"], id)
	}

	c.roundTrip(2, "tools/call", map[string]any{"name": "read_failing", "_meta": map[string]any{"progressToken": 7}})
	if rec := waitResult(t, logs, "read_failing"); rec["outcome"] != "tool_error" || rec["error"] != nil || rec["progress_token"] != "7" {
		t.Fatalf("tool error in digest mode: %+v", rec)
	}
	c.roundTrip(3, "tools/call", map[string]any{"name": "read_failing_full"})
	rec = waitResult(t, logs, "read_failing_full")
	if text, _ := rec["error"].(string); rec["outcome"] != "tool_error" || !strings.HasPrefix(text, "zypper exited 4 eee") ||
		len(text) > maxResultError+len("…") || rec["progress_token"] != nil {
		t.Fatalf("tool error with audit full: %+v", rec)
	}

	c.roundTrip(4, "tools/call", map[string]any{"name": "read_rpcerror"})
	if rec := waitResult(t, logs, "read_rpcerror"); rec["outcome"] != "error" {
		t.Fatalf("rpc error: %+v", rec)
	}

	c.send(5, "tools/call", map[string]any{"name": "slow"})
	waitBusy(t, r, "fs")
	n, _ := jsonrpc.NewNotification("notifications/cancelled", map[string]any{"requestId": 5})
	c.write(n)
	if rec := waitResult(t, logs, "slow"); rec["outcome"] != "cancelled" {
		t.Fatalf("cancelled: %+v", rec)
	}

	if m := c.roundTrip(6, "tools/call", map[string]any{"name": "read_crash"}); m.Error == nil {
		t.Fatalf("a dying server answered: %+v", m)
	}
	if rec := waitResult(t, logs, "read_crash"); rec["outcome"] != "error" {
		t.Fatalf("server died: %+v", rec)
	}

	// Denied calls are not forwarded, and have no record.
	c.roundTrip(7, "tools/call", map[string]any{"name": "delete_file"})
	time.Sleep(20 * time.Millisecond)
	for _, rec := range resultRecords(t, logs) {
		if rec["name"] == "delete_file" {
			t.Fatalf("a denied call has a result: %+v", rec)
		}
	}
}

// A call that a client never reads the answer of is recorded all the
// same: the record is written when the server answers.
func TestResultRecordWithoutReader(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	logs := &syncWriter{w: &strings.Builder{}}
	r.Audit = audit.New(logs)
	c := connect(t, r, alice(), "fs", nil)
	c.send(1, "tools/call", map[string]any{"name": "read_failing"})
	if rec := waitResult(t, logs, "read_failing"); rec["outcome"] != "tool_error" {
		t.Fatalf("%+v", rec)
	}
}

// An approved call's record names the approval and the grant it made; a
// call allowed by a stored grant names the grant.
func TestResultRecordApproval(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	r.PDP = askPDP{channel: pep.ChannelOOB, ask: map[string]bool{"write_file": true}}
	r.Broker = mustBroker(t, broker.Options{Timeout: 5 * time.Second, OOB: true})
	logs := &syncWriter{w: &strings.Builder{}}
	r.Audit = audit.New(logs)
	c := connect(t, r, alice(), "fs", nil)

	c.send(1, "tools/call", map[string]any{"name": "write_file"})
	root := broker.Approver{Name: "root", UID: 0}
	var id string
	for i := 0; i < 400 && id == ""; i++ {
		if ps := r.Broker.ListPending(context.Background(), root); len(ps) == 1 {
			id = ps[0].ID
		}
		time.Sleep(5 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("no approval pending")
	}
	g, err := r.Broker.Resolve(context.Background(), root, id, true, "session")
	if err != nil {
		t.Fatal(err)
	}
	if g.ApprovalID != id {
		t.Fatalf("grant's approval id %q, want %q", g.ApprovalID, id)
	}
	rec := waitResult(t, logs, "write_file")
	if rec["outcome"] != "ok" || rec["approval_id"] != id || rec["grant"] != g.ID {
		t.Fatalf("approved: %+v (approval %s, grant %s)", rec, id, g.ID)
	}

	// The next call is allowed by the session's grant.
	logs.mu.Lock()
	logs.w.Reset()
	logs.mu.Unlock()
	for {
		if m := c.read(); m.Key() == "1" {
			break
		}
	}
	c.roundTrip(2, "tools/call", map[string]any{"name": "write_file"})
	rec = waitResult(t, logs, "write_file")
	if rec["grant"] != g.ID || rec["outcome"] != "ok" {
		t.Fatalf("by grant: %+v (grant %s)", rec, g.ID)
	}
}
