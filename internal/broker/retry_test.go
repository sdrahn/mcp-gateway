package broker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/pep"
)

// A parked approval has no waiting call until a retry waits for it; the
// retry learns the decision, or that nobody decided yet, or that the
// approval is gone.
func TestParkAndAwait(t *testing.T) {
	b, err := New(Options{Timeout: time.Minute, OOB: true, URLTemplate: "https://gw.example.com/a/{id}"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	in := input()
	ask := pep.AskSpec{Channel: pep.ChannelURL, Scopes: []string{"once"}}
	id := b.Park(in, ask, pep.ChannelURL)
	if p := b.ListPending(ctx, aliceApprover); len(p) != 1 || p[0].ID != id || p[0].Waiting {
		t.Fatalf("parked: %+v", p)
	}
	if u := b.URLParams(in, ask, id); u.URL != "https://gw.example.com/a/"+id || u.ElicitationID != id {
		t.Errorf("url params %+v", u)
	}
	// The same request parked again: the same approval.
	if again := b.Park(in, ask, pep.ChannelURL); again != id {
		t.Errorf("parked again: %s", again)
	}

	if _, out := b.Await(ctx, id, alice, 10*time.Millisecond); out != Waiting {
		t.Fatalf("nobody decided: %v", out)
	}
	bob := alice
	bob.Sub = "bob"
	if _, out := b.Await(ctx, id, bob, time.Second); out != Gone {
		t.Errorf("someone else's: %v", out)
	}

	// Decided while a retry waits: the grant ("once", not stored).
	go func() {
		for {
			if p := b.ListPending(ctx, aliceApprover); len(p) == 1 && p[0].Waiting {
				_, _ = b.Resolve(ctx, aliceApprover, id, true, "once")
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	g, out := b.Await(ctx, id, alice, 5*time.Second)
	if out != Decided || g == nil || g.Scope != "once" {
		t.Fatalf("decided: %v %+v", out, g)
	}
	if _, out := b.Await(ctx, id, alice, time.Second); out != Gone {
		t.Errorf("after the decision: %v", out)
	}

	// Decided while no retry waits: the "once" grant is kept for the call.
	id = b.Park(in, ask, pep.ChannelOOB)
	if _, err := b.Resolve(ctx, aliceApprover, id, true, "once"); err != nil {
		t.Fatal(err)
	}
	if _, out := b.Await(ctx, id, alice, time.Second); out != Gone {
		t.Errorf("decided earlier: %v", out)
	}
	if _, ok := b.TakeOnce(alice, "fs", "write_file"); !ok {
		t.Error("no once grant kept")
	}

	// Withdrawn.
	id = b.Park(in, ask, pep.ChannelURL)
	b.Withdraw(id, alice)
	if len(b.ListPending(ctx, aliceApprover)) != 0 {
		t.Error("withdrawn approval still pending")
	}
}

// The approval form and its answer.
func TestFormAnswer(t *testing.T) {
	b, err := New(Options{Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	in := input()
	ask := pep.AskSpec{Channel: pep.ChannelForm, Scopes: []string{"once", "1h"}}
	if f := FormParams(in, ask); !strings.Contains(f.Message, "write_file") {
		t.Errorf("form %+v", f)
	}
	if g, err := b.FormAnswer(in, ask, ElicitResult{Action: "decline"}); g != nil || err != nil {
		t.Errorf("declined: %+v %v", g, err)
	}
	g, err := b.FormAnswer(in, ask, ElicitResult{Action: "accept", Content: map[string]any{"scope": "1h"}})
	if err != nil || g == nil || g.Scope != "duration" || len(b.Grants(alice, "fs", "write_file")) != 1 {
		t.Fatalf("accepted: %+v %v", g, err)
	}
	if _, err := b.FormAnswer(in, ask, ElicitResult{Action: "accept", Content: map[string]any{"scope": "session"}}); err == nil {
		t.Error("a scope not offered accepted")
	}
	if c, err := b.Channel(&fakeElicitor{}, ask); err != ErrNoChannel {
		t.Errorf("channel without form: %v %v", c, err)
	}
}

// An approval no call waits for (approvals.no_wait) stays pending for
// NoWaitTTL, a retry takes it over, and a denial of it answers the next
// attempt once.
func TestParkForAndTakeDenial(t *testing.T) {
	b := newBroker(t, nil)
	ask := pep.AskSpec{Channel: pep.ChannelOOB, Scopes: []string{"once", "1h"}}
	id, expires := b.ParkFor(input(), ask, pep.ChannelOOB, NoWaitTTL)
	if left := time.Until(expires); left < NoWaitTTL-time.Minute || left > NoWaitTTL {
		t.Errorf("expires in %v, want about %v (not the timeout of 2s)", left, NoWaitTTL)
	}
	ps := b.ListPending(context.Background(), admin)
	if len(ps) != 1 || ps[0].ID != id || ps[0].Waiting {
		t.Fatalf("pending %+v", ps)
	}
	if again, _ := b.ParkFor(input(), ask, pep.ChannelOOB, NoWaitTTL); again != id {
		t.Errorf("retry parked %s, not %s", again, id)
	}
	// Another request is a pending approval of its own.
	other := input()
	other.Args = map[string]any{"path": "/home/alice/y"}
	if oid, _ := b.ParkFor(other, ask, pep.ChannelOOB, NoWaitTTL); oid == id {
		t.Error("another request took the approval over")
	}
	if b.TakeDenial(input()) {
		t.Error("a denial before any was made")
	}
	if _, err := b.Resolve(context.Background(), admin, id, false, ""); err != nil {
		t.Fatal(err)
	}
	if b.TakeDenial(other) {
		t.Error("the denial answered another request")
	}
	if !b.TakeDenial(input()) {
		t.Error("the denial does not answer the next attempt")
	}
	if b.TakeDenial(input()) {
		t.Error("the denial was not used up")
	}
	// Approved with "once": the next attempt's grant.
	id, _ = b.ParkFor(input(), ask, pep.ChannelOOB, NoWaitTTL)
	if _, err := b.Resolve(context.Background(), admin, id, true, "once"); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.TakeOnce(alice, "fs", "write_file"); !ok {
		t.Error("no once grant for the next attempt")
	}
	if b.TakeDenial(input()) {
		t.Error("an approval read as a denial")
	}
}

// A denial is kept NoWaitTTL only.
func TestTakeDenialExpires(t *testing.T) {
	b := newBroker(t, nil)
	clock := time.Now()
	b.now = func() time.Time { return clock }
	id, _ := b.ParkFor(input(), pep.AskSpec{Channel: pep.ChannelOOB, Scopes: []string{"once"}}, pep.ChannelOOB, NoWaitTTL)
	if _, err := b.Resolve(context.Background(), admin, id, false, ""); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(NoWaitTTL + time.Second)
	if b.TakeDenial(input()) {
		t.Error("an expired denial answered")
	}
}
