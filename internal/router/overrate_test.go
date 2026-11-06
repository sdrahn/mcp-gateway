package router

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/pep"
)

func overRateRouter(t *testing.T) (*Router, *syncWriter) {
	t.Helper()
	r, _ := testRouter(t, time.Hour)
	r.Broker = mustBroker(t, broker.Options{Timeout: 5 * time.Second, OOB: true})
	logs := &syncWriter{w: &strings.Builder{}}
	r.Audit = audit.New(logs)
	r.RetryWait = 100 * time.Millisecond
	return r, logs
}

// answer reads until the response to id.
func answer(c *client, id string) (string, bool) {
	c.t.Helper()
	for {
		if m := c.read(); m.Key() == id {
			return toolText(c.t, m)
		}
	}
}

// approval_over_rate 2/m: two calls run, the third waits for an approval
// (out of band, once only, the rate named); approved, it runs and is not
// counted, so the fourth asks again; declined, it is denied.
func TestApprovalOverRate(t *testing.T) {
	r, logs := overRateRouter(t)
	root := broker.Approver{Name: "root", UID: 0}
	c := connect(t, r, alice(), "fs", nil)
	for i := 1; i <= 2; i++ {
		if text, isErr := toolText(t, c.roundTrip(i, "tools/call", map[string]any{"name": "read_overrate"})); isErr || text != "fs did read_overrate" {
			t.Fatalf("call %d within the rate: %q", i, text)
		}
	}
	if ps := r.Broker.ListPending(context.Background(), root); len(ps) != 0 {
		t.Fatalf("an approval within the rate: %+v", ps)
	}
	c.send(3, "tools/call", map[string]any{"name": "read_overrate"})
	p := pendingOne(t, r.Broker)
	if p.OverRate != "2/m" || strings.Join(p.Scopes, ",") != "once" || p.Channel != pep.ChannelOOB ||
		!strings.Contains(p.Prompt, "Rate 2/m reached for alice on fs read_overrate") {
		t.Fatalf("approval %+v", p)
	}
	if _, err := r.Broker.Resolve(context.Background(), root, p.ID, true, "once"); err != nil {
		t.Fatal(err)
	}
	if text, isErr := answer(c, "3"); isErr || text != "fs did read_overrate" {
		t.Fatalf("approved: %q", text)
	}
	// The approved call was not counted: still two in the minute.
	c.send(4, "tools/call", map[string]any{"name": "read_overrate"})
	p = pendingOne(t, r.Broker)
	if _, err := r.Broker.Resolve(context.Background(), root, p.ID, false, ""); err != nil {
		t.Fatal(err)
	}
	if text, isErr := answer(c, "4"); !isErr || !strings.Contains(text, "declined") {
		t.Fatalf("declined: %q %v", text, isErr)
	}
	out := logs.String()
	if strings.Count(out, `"over_rate":"2/m"`) != 2 || !strings.Contains(out, `"effect":"allow","name":"read_overrate"`) {
		t.Fatalf("decision records: %s", out)
	}
}

// With rate_limit too, the hard cap denies first, without asking.
func TestApprovalOverRateHardCap(t *testing.T) {
	r, _ := overRateRouter(t)
	c := connect(t, r, alice(), "fs", nil)
	for i := 1; i <= 2; i++ {
		if _, isErr := toolText(t, c.roundTrip(i, "tools/call", map[string]any{"name": "read_overcap"})); isErr {
			t.Fatalf("call %d", i)
		}
	}
	if text, isErr := toolText(t, c.roundTrip(3, "tools/call", map[string]any{"name": "read_overcap"})); !isErr || !strings.Contains(text, "rate limit exceeded") {
		t.Fatalf("over the hard cap: %q %v", text, isErr)
	}
	if ps := r.Broker.ListPending(context.Background(), broker.Approver{Name: "root"}); len(ps) != 0 {
		t.Fatalf("asked over the hard cap: %+v", ps)
	}
}

// An agent of 2026-07-28 waits for such an approval in rounds; approved,
// the retry runs and is not counted.
func TestApprovalOverRateAgent(t *testing.T) {
	r, _ := overRateRouter(t)
	c := agent(t, r, alice(), "fs")
	call := map[string]any{"name": "read_overrate"}
	for i := 1; i <= 2; i++ {
		if text, isErr := toolText(t, c.roundTrip(i, "tools/call", withAgentMeta(call, nil))); isErr || text != "fs did read_overrate" {
			t.Fatalf("call %d: %q", i, text)
		}
	}
	ir := inputRequiredOf(t, c.roundTrip(3, "tools/call", withAgentMeta(call, nil)))
	ps := r.Broker.ListPending(t.Context(), self)
	if len(ps) != 1 || ps[0].OverRate != "2/m" || strings.Join(ps[0].Scopes, ",") != "once" {
		t.Fatalf("pending %+v", ps)
	}
	// A retry before the decision waits again for the same approval.
	ir = inputRequiredOf(t, c.roundTrip(4, "tools/call", retry(call, ir.RequestState, nil, nil)))
	if again := r.Broker.ListPending(t.Context(), self); len(again) != 1 || again[0].ID != ps[0].ID {
		t.Fatalf("after a retry %+v", again)
	}
	if _, err := r.Broker.Resolve(t.Context(), self, ps[0].ID, true, "once"); err != nil {
		t.Fatal(err)
	}
	if text, isErr := toolText(t, c.roundTrip(5, "tools/call", retry(call, ir.RequestState, nil, nil))); isErr || text != "fs did read_overrate" {
		t.Fatalf("approved: %q", text)
	}
	// Not counted: the next asks again.
	inputRequiredOf(t, c.roundTrip(6, "tools/call", withAgentMeta(call, nil)))
}
