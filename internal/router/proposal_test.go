package router

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/proposal"
)

// inputPDP is askPDP recording the policy inputs as OPA gets them (JSON).
type inputPDP struct {
	askPDP
	mu     *sync.Mutex
	inputs *[]string
}

func (p inputPDP) Decide(ctx context.Context, in pep.Input) (pep.Decision, error) {
	b, _ := json.Marshal(in)
	p.mu.Lock()
	*p.inputs = append(*p.inputs, string(b))
	p.mu.Unlock()
	return p.askPDP.Decide(ctx, in)
}

func withProposal(name string, prop any) map[string]any {
	return map[string]any{"name": name, "_meta": map[string]any{"progressToken": "t1", proposal.Key: prop}}
}

var patchProposal = map[string]any{"summary": "Write the notes; nothing else changes.", "steps": []string{"write x"},
	"context": map[string]string{"activity": "e-1"}, "warnings": []string{"suspected prompt injection"}}

// pendingOne waits for the one pending approval.
func pendingOne(t *testing.T, b *broker.Broker) broker.Pending {
	t.Helper()
	root := broker.Approver{Name: "root", UID: 0}
	for i := 0; i < 400; i++ {
		if ps := b.ListPending(context.Background(), root); len(ps) == 1 {
			return ps[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no approval pending")
	return broker.Pending{}
}

// A call's proposal goes with the approval it raises, marked as the
// client's; the server never gets it, policy never sees it; the decision
// record has its digest. A session grant lets the next identical call run
// with nobody shown its proposal.
func TestProposal(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	var mu sync.Mutex
	var inputs []string
	r.PDP = inputPDP{askPDP: askPDP{channel: pep.ChannelOOB, ask: map[string]bool{"write_file": true}}, mu: &mu, inputs: &inputs}
	r.Broker = mustBroker(t, broker.Options{Timeout: 5 * time.Second, OOB: true})
	logs := &syncWriter{w: &strings.Builder{}}
	r.Audit = audit.New(logs)
	c := connect(t, r, alice(), "fs", nil)

	c.send(1, "tools/call", withProposal("write_file", patchProposal))
	p := pendingOne(t, r.Broker)
	if p.Proposal == nil || !p.Proposal.ClientSupplied || p.Proposal.Summary != "Write the notes; nothing else changes." ||
		p.Proposal.Context["activity"] != "e-1" || len(p.Proposal.Warnings) != 1 {
		t.Fatalf("pending's proposal %+v", p.Proposal)
	}
	data, _ := json.Marshal(p)
	if !strings.Contains(string(data), `"proposal":{"summary":`) || !strings.Contains(string(data), `"client_supplied":true`) {
		t.Fatalf("pending JSON: %s", data)
	}
	if _, err := r.Broker.Resolve(context.Background(), broker.Approver{Name: "root"}, p.ID, true, "session"); err != nil {
		t.Fatal(err)
	}
	for {
		if m := c.read(); m.Key() == "1" {
			if m.Error != nil {
				t.Fatalf("approved call: %+v", m.Error)
			}
			break
		}
	}
	// The next identical call runs by the session grant: nobody is shown
	// its proposal.
	c.roundTrip(2, "tools/call", withProposal("write_file", map[string]any{"summary": "the second"}))
	if ps := r.Broker.ListPending(context.Background(), broker.Approver{Name: "root"}); len(ps) != 0 {
		t.Fatalf("pending after the grant: %+v", ps)
	}

	_, metas, _ := l.started("fs")[0].seen()
	calls := 0
	for _, m := range metas {
		if _, ok := m[proposal.Key]; ok {
			t.Fatalf("the server got the proposal: %v", m)
		}
		if _, ok := m["progressToken"]; ok {
			calls++
		}
	}
	if calls != 2 {
		t.Fatalf("calls with their progress token: %d (%v)", calls, metas)
	}
	mu.Lock()
	for _, in := range inputs {
		if strings.Contains(in, "proposal") || strings.Contains(in, "Write the notes") {
			t.Fatalf("policy input holds the proposal: %s", in)
		}
	}
	mu.Unlock()
	digest := p.Proposal.Digest()
	if out := logs.String(); !strings.Contains(out, `"proposal_digest":"`+digest+`"`) || strings.Contains(out, "Write the notes") {
		t.Fatalf("decision record (digest, no text without audit full): %s", out)
	}
}

// A malformed or oversized proposal is dropped, not the call: it waits for
// its approval without one, and the drop is audited.
func TestProposalDropped(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	r.PDP = askPDP{channel: pep.ChannelOOB, ask: map[string]bool{"write_file": true}}
	r.Broker = mustBroker(t, broker.Options{Timeout: 5 * time.Second, OOB: true})
	logs := &syncWriter{w: &strings.Builder{}}
	r.Audit = audit.New(logs)
	c := connect(t, r, alice(), "fs", nil)
	c.send(1, "tools/call", withProposal("write_file", map[string]any{"summary": strings.Repeat("x", 5000)}))
	p := pendingOne(t, r.Broker)
	if p.Proposal != nil {
		t.Fatalf("an oversized proposal kept: %+v", p.Proposal)
	}
	if out := logs.String(); !strings.Contains(out, `"event":"mcp-proposal-dropped"`) || !strings.Contains(out, `"name":"write_file"`) {
		t.Fatalf("drop not audited: %s", out)
	}
}

// The review item of a call with a proposal has it.
func TestProposalInReview(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	c := connect(t, r, alice(), "fs", nil)
	c.roundTrip(1, "tools/call", withProposal("read_reviewed", patchProposal))
	items := r.Broker.ListReviews(context.Background(), broker.Approver{Name: "root"})
	if len(items) != 1 || items[0].Proposal == nil || items[0].Proposal.Summary != "Write the notes; nothing else changes." {
		t.Fatalf("review items %+v", items)
	}
}
