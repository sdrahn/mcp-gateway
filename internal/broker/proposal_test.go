package broker

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/proposal"
)

// A pending approval keeps the call's proposal, also across a restart,
// and the approval's audit record names its digest.
func TestApprovalProposal(t *testing.T) {
	k := &kernelLog{}
	file := t.TempDir() + "/pending.json"
	b := newBroker(t, func(o *Options) {
		o.Audit = audit.New(io.Discard, audit.Options{Kernel: k})
		o.PendingFile = file
	})
	pr, err := proposal.Parse(json.RawMessage(`{"summary": "Write the notes.", "warnings": ["suspected prompt injection"]}`))
	if err != nil {
		t.Fatal(err)
	}
	in := input()
	in.Proposal = pr
	go func() { _, _ = b.Approve(context.Background(), &fakeElicitor{}, in, urlAsk) }()
	var p Pending
	for i := 0; i < 200 && p.ID == ""; i++ {
		if ps := b.ListPending(context.Background(), admin); len(ps) > 0 {
			p = ps[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	if p.Proposal == nil || p.Proposal.Summary != "Write the notes." || !p.Proposal.ClientSupplied {
		t.Fatalf("pending %+v", p)
	}
	restored := newBroker(t, func(o *Options) { o.PendingFile = file })
	if ps := restored.ListPending(context.Background(), admin); len(ps) != 1 || ps[0].Proposal == nil || ps[0].Proposal.Summary != "Write the notes." {
		t.Fatalf("restored %+v", ps)
	}
	if _, err := b.Resolve(context.Background(), admin, p.ID, true, "once"); err != nil {
		t.Fatal(err)
	}
	if len(k.msgs) != 1 || !strings.Contains(k.msgs[0], "op=mcp-approval") || !strings.Contains(k.msgs[0], "proposal_digest="+pr.Digest()) {
		t.Fatalf("audit %v", k.msgs)
	}
}

// An approval asked over a rate (approval_over_rate) carries the rate, and
// so does its audit record.
func TestApprovalOverRateRecorded(t *testing.T) {
	k := &kernelLog{}
	b := newBroker(t, func(o *Options) { o.Audit = audit.New(io.Discard, audit.Options{Kernel: k}) })
	ask := pep.AskSpec{Channel: pep.ChannelOOB, Prompt: "Rate 2/m reached", Scopes: []string{"once"}, OverRate: "2/m"}
	go func() { _, _ = b.Approve(context.Background(), &fakeElicitor{}, input(), ask) }()
	var p Pending
	for i := 0; i < 200 && p.ID == ""; i++ {
		if ps := b.ListPending(context.Background(), admin); len(ps) > 0 {
			p = ps[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	data, _ := json.Marshal(p)
	if p.OverRate != "2/m" || !strings.Contains(string(data), `"over_rate":"2/m"`) {
		t.Fatalf("pending %s", data)
	}
	if _, err := b.Resolve(context.Background(), admin, p.ID, true, "once"); err != nil {
		t.Fatal(err)
	}
	if len(k.msgs) != 1 || !strings.Contains(k.msgs[0], "over_rate=2/m") {
		t.Fatalf("audit %v", k.msgs)
	}
}
