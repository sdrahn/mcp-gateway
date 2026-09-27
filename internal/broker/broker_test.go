package broker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

type fakeElicitor struct {
	form   bool
	result ElicitResult
	err    error
	got    *ElicitParams
}

func (f *fakeElicitor) SupportsForm() bool { return f.form }

func (f *fakeElicitor) Elicit(_ context.Context, p ElicitParams) (ElicitResult, error) {
	f.got = &p
	return f.result, f.err
}

var alice = principal.Principal{Sub: "alice", SessionID: "s1"}

func input() pep.Input {
	return pep.Input{
		Principal: alice,
		Action:    "tools.call",
		Resource:  pep.Resource{Server: "fs", Kind: "tool", Name: "write_file"},
		Args:      map[string]any{"path": "/home/alice/x"},
	}
}

var formAsk = pep.AskSpec{Channel: pep.ChannelForm, Prompt: "Write?", Scopes: []string{"once", "session"}}

func TestApproveSession(t *testing.T) {
	b := New(time.Second)
	el := &fakeElicitor{form: true, result: ElicitResult{Action: "accept", Content: map[string]any{"scope": "session"}}}
	g, err := b.Approve(context.Background(), el, input(), formAsk)
	if err != nil || g == nil {
		t.Fatalf("grant %+v, err %v", g, err)
	}
	if g.Scope != "session" || g.Channel != pep.ChannelForm || g.SessionID != "s1" {
		t.Errorf("grant %+v", g)
	}
	if got := b.Grants(alice, "fs", "write_file"); len(got) != 1 {
		t.Errorf("stored grants %+v", got)
	}
	if got := b.Grants(alice, "fs", "delete_file"); len(got) != 0 {
		t.Errorf("grants for other tool %+v", got)
	}
	if el.got == nil || el.got.RequestedSchema["required"] == nil {
		t.Errorf("elicitation params %+v", el.got)
	}
	b.EndSession("s1")
	if got := b.Grants(alice, "fs", "write_file"); len(got) != 0 {
		t.Errorf("grants after EndSession %+v", got)
	}
}

func TestApproveOnceNotStored(t *testing.T) {
	b := New(time.Second)
	el := &fakeElicitor{form: true, result: ElicitResult{Action: "accept", Content: map[string]any{"scope": "once"}}}
	g, err := b.Approve(context.Background(), el, input(), formAsk)
	if err != nil || g == nil || g.Scope != "once" {
		t.Fatalf("grant %+v, err %v", g, err)
	}
	if got := b.Grants(alice, "fs", "write_file"); len(got) != 0 {
		t.Errorf("once grant stored: %+v", got)
	}
}

func TestApproveDuration(t *testing.T) {
	b := New(time.Second)
	ask := formAsk
	ask.Scopes = []string{"2h"}
	el := &fakeElicitor{form: true, result: ElicitResult{Action: "accept", Content: map[string]any{"scope": "2h"}}}
	g, err := b.Approve(context.Background(), el, input(), ask)
	if err != nil || g == nil || g.Scope != "duration" {
		t.Fatalf("grant %+v, err %v", g, err)
	}
}

func TestApproveExpired(t *testing.T) {
	b := New(time.Second)
	el := &fakeElicitor{form: true, result: ElicitResult{Action: "accept", Content: map[string]any{"scope": "session"}}}
	if _, err := b.Approve(context.Background(), el, input(), formAsk); err != nil {
		t.Fatal(err)
	}
	b.now = func() time.Time { return time.Now().Add(SessionTTL + time.Minute) }
	if got := b.Grants(alice, "fs", "write_file"); len(got) != 0 {
		t.Errorf("expired grant returned: %+v", got)
	}
}

func TestApproveDeclined(t *testing.T) {
	for _, action := range []string{"decline", "cancel"} {
		b := New(time.Second)
		el := &fakeElicitor{form: true, result: ElicitResult{Action: action}}
		g, err := b.Approve(context.Background(), el, input(), formAsk)
		if err != nil || g != nil {
			t.Errorf("%s: grant %+v, err %v", action, g, err)
		}
	}
}

func TestApproveRejectsUnofferedScope(t *testing.T) {
	b := New(time.Second)
	el := &fakeElicitor{form: true, result: ElicitResult{Action: "accept", Content: map[string]any{"scope": "forever"}}}
	if g, err := b.Approve(context.Background(), el, input(), formAsk); err == nil || g != nil {
		t.Fatalf("grant %+v, err %v", g, err)
	}
}

func TestApproveChannels(t *testing.T) {
	b := New(time.Second)
	accept := ElicitResult{Action: "accept", Content: map[string]any{"scope": "once"}}

	// URL channel is not available in the PoC and no form fallback: denied.
	urlAsk := pep.AskSpec{Channel: pep.ChannelURL, Fallback: "oob", Scopes: []string{"once"}}
	if _, err := b.Approve(context.Background(), &fakeElicitor{form: true, result: accept}, input(), urlAsk); !errors.Is(err, ErrNoChannel) {
		t.Errorf("url ask: err %v", err)
	}
	// Form requested but the client cannot do it.
	if _, err := b.Approve(context.Background(), &fakeElicitor{form: false, result: accept}, input(), formAsk); !errors.Is(err, ErrNoChannel) {
		t.Errorf("no form support: err %v", err)
	}
	// Form as explicit fallback.
	urlFormAsk := pep.AskSpec{Channel: pep.ChannelURL, Fallback: "form", Scopes: []string{"once"}}
	if g, err := b.Approve(context.Background(), &fakeElicitor{form: true, result: accept}, input(), urlFormAsk); err != nil || g == nil {
		t.Errorf("form fallback: grant %+v, err %v", g, err)
	}
}
