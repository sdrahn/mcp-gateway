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
