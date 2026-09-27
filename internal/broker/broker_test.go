package broker

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

type fakeElicitor struct {
	form, url bool
	result    ElicitResult
	err       error

	mu       sync.Mutex
	got      []any
	notified []string
	elicited chan any
}

func (f *fakeElicitor) SupportsForm() bool { return f.form }
func (f *fakeElicitor) SupportsURL() bool  { return f.url }

func (f *fakeElicitor) Elicit(_ context.Context, p any) (ElicitResult, error) {
	f.mu.Lock()
	f.got = append(f.got, p)
	f.mu.Unlock()
	if f.elicited != nil {
		f.elicited <- p
	}
	return f.result, f.err
}

func (f *fakeElicitor) Notify(method string, _ any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notified = append(f.notified, method)
}

func (f *fakeElicitor) notifications() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.notified...)
}

var aliceUID = uint32(1001)

var alice = principal.Principal{Sub: "alice", UID: &aliceUID, SessionID: "s1", Transport: principal.TransportUnix}

var (
	aliceApprover = Approver{Name: "alice", UID: 1001}
	bobApprover   = Approver{Name: "bob", UID: 1002}
	admin         = Approver{Name: "carol", UID: 1003, Groups: []string{"wheel"}}
)

func input() pep.Input {
	return pep.Input{
		Principal: alice,
		Action:    "tools.call",
		Resource:  pep.Resource{Server: "fs", Kind: "tool", Name: "write_file"},
		Args:      map[string]any{"path": "/home/alice/x"},
	}
}

func newBroker(t *testing.T, mod func(*Options)) *Broker {
	t.Helper()
	o := Options{Timeout: 2 * time.Second, AdminGroup: "wheel", OOB: true, URLTemplate: "https://gw/approvals/{id}"}
	if mod != nil {
		mod(&o)
	}
	b, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var formAsk = pep.AskSpec{Channel: pep.ChannelForm, Prompt: "Write?", Scopes: []string{"once", "session", "24h"}}

func TestFormSession(t *testing.T) {
	b := newBroker(t, nil)
	el := &fakeElicitor{form: true, result: ElicitResult{Action: "accept", Content: map[string]any{"scope": "session"}}}
	g, err := b.Approve(context.Background(), el, input(), formAsk)
	if err != nil || g == nil || g.Scope != "session" || g.Channel != pep.ChannelForm || g.ApprovedBy != "alice" {
		t.Fatalf("grant %+v, err %v", g, err)
	}
	if got := b.Grants(alice, "fs", "write_file"); len(got) != 1 {
		t.Errorf("grants %+v", got)
	}
	other := alice
	other.SessionID = "s2"
	if got := b.Grants(other, "fs", "write_file"); len(got) != 0 {
		t.Errorf("session grant leaked into another session: %+v", got)
	}
	b.EndSession("s1")
	if got := b.Grants(alice, "fs", "write_file"); len(got) != 0 {
		t.Errorf("grants after EndSession %+v", got)
	}
}

func TestFormOnceAndDecline(t *testing.T) {
	b := newBroker(t, nil)
	el := &fakeElicitor{form: true, result: ElicitResult{Action: "accept", Content: map[string]any{"scope": "once"}}}
	if g, err := b.Approve(context.Background(), el, input(), formAsk); err != nil || g == nil || g.Scope != "once" {
		t.Fatalf("grant %+v, err %v", g, err)
	}
	if got := b.Grants(alice, "fs", "write_file"); len(got) != 0 {
		t.Errorf("once grant stored: %+v", got)
	}
	for _, action := range []string{"decline", "cancel"} {
		el := &fakeElicitor{form: true, result: ElicitResult{Action: action}}
		if g, err := b.Approve(context.Background(), el, input(), formAsk); err != nil || g != nil {
			t.Errorf("%s: grant %+v err %v", action, g, err)
		}
	}
	el = &fakeElicitor{form: true, result: ElicitResult{Action: "accept", Content: map[string]any{"scope": "forever"}}}
	if g, err := b.Approve(context.Background(), el, input(), formAsk); !errors.Is(err, ErrBadScope) || g != nil {
		t.Errorf("unoffered scope: grant %+v err %v", g, err)
	}
}

// resolveWhenPending approves the first pending approval once it appears.
func resolveWhenPending(t *testing.T, b *Broker, a Approver, approve bool, scope string) chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if ps := b.ListPending(admin); len(ps) > 0 {
				_, err := b.Resolve(a, ps[0].ID, approve, scope)
				done <- err
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		done <- errors.New("no pending approval")
	}()
	return done
}

var urlAsk = pep.AskSpec{Channel: pep.ChannelURL, Fallback: "oob", Prompt: "Write?", Scopes: []string{"once", "session", "24h"}}

func TestURLApproved(t *testing.T) {
	b := newBroker(t, nil)
	el := &fakeElicitor{url: true, result: ElicitResult{Action: "accept"}, elicited: make(chan any, 1)}
	done := resolveWhenPending(t, b, aliceApprover, true, "24h")
	g, err := b.Approve(context.Background(), el, input(), urlAsk)
	if err != nil || g == nil || g.Channel != pep.ChannelURL || g.Scope != "duration" || g.ApprovedBy != "alice" {
		t.Fatalf("grant %+v err %v", g, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	p := (<-el.elicited).(URLElicitParams)
	if p.Mode != "url" || p.URL != "https://gw/approvals/"+p.ElicitationID {
		t.Fatalf("url params %+v", p)
	}
	if n := el.notifications(); len(n) != 1 || n[0] != "notifications/elicitation/complete" {
		t.Fatalf("notifications %v", n)
	}
	if len(b.ListPending(admin)) != 0 {
		t.Fatal("approval still pending")
	}
}

func TestURLDeclinedToOpen(t *testing.T) {
	b := newBroker(t, nil)
	el := &fakeElicitor{url: true, result: ElicitResult{Action: "decline"}}
	if g, err := b.Approve(context.Background(), el, input(), urlAsk); err != nil || g != nil {
		t.Fatalf("grant %+v err %v", g, err)
	}
}

func TestOOBDeniedByAdmin(t *testing.T) {
	b := newBroker(t, nil)
	el := &fakeElicitor{} // no elicitation support at all
	done := resolveWhenPending(t, b, admin, false, "")
	g, err := b.Approve(context.Background(), el, input(), urlAsk) // url unsupported → oob
	if err != nil || g != nil {
		t.Fatalf("grant %+v err %v", g, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n := el.notifications(); len(n) != 1 || n[0] != "notifications/message" {
		t.Fatalf("notifications %v", n)
	}
}

func TestOOBTimeout(t *testing.T) {
	b := newBroker(t, func(o *Options) { o.Timeout = 50 * time.Millisecond })
	if _, err := b.Approve(context.Background(), &fakeElicitor{}, input(), urlAsk); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
	if len(b.ListPending(admin)) != 0 {
		t.Fatal("timed-out approval still pending")
	}
}

func TestNoChannel(t *testing.T) {
	b := newBroker(t, func(o *Options) { o.OOB, o.URLTemplate = false, "" })
	for _, el := range []*fakeElicitor{{url: true}, {}} {
		if _, err := b.Approve(context.Background(), el, input(), urlAsk); !errors.Is(err, ErrNoChannel) {
			t.Errorf("err %v", err)
		}
	}
	if _, err := b.Approve(context.Background(), &fakeElicitor{}, input(), formAsk); !errors.Is(err, ErrNoChannel) {
		t.Errorf("form without support: err %v", err)
	}
}

func TestApproverAuthorization(t *testing.T) {
	b := newBroker(t, nil)
	go func() { _, _ = b.Approve(context.Background(), &fakeElicitor{}, input(), urlAsk) }()
	var id string
	for i := 0; i < 200 && id == ""; i++ {
		if ps := b.ListPending(admin); len(ps) > 0 {
			id = ps[0].ID
		}
		time.Sleep(5 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("no pending approval")
	}
	if ps := b.ListPending(bobApprover); len(ps) != 0 {
		t.Fatalf("bob sees alice's approvals: %+v", ps)
	}
	if _, err := b.GetPending(bobApprover, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bob get: %v", err)
	}
	if _, err := b.Resolve(bobApprover, id, true, "once"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bob resolve: %v", err)
	}
	if _, err := b.Resolve(aliceApprover, id, true, "forever"); !errors.Is(err, ErrBadScope) {
		t.Fatalf("bad scope: %v", err)
	}
	if ps := b.ListPending(aliceApprover); len(ps) != 1 {
		t.Fatalf("alice sees %d approvals", len(ps))
	}
	if _, err := b.Resolve(aliceApprover, id, true, "once"); err != nil {
		t.Fatalf("alice resolve: %v", err)
	}
}

func TestRemotePrincipalNeedsAdmin(t *testing.T) {
	b := newBroker(t, nil)
	in := input()
	in.Principal = principal.Principal{Sub: "u-remote", Issuer: "https://idp", Transport: principal.TransportHTTP, SessionID: "r1"}
	go func() { _, _ = b.Approve(context.Background(), &fakeElicitor{}, in, urlAsk) }()
	var id string
	for i := 0; i < 200 && id == ""; i++ {
		if ps := b.ListPending(admin); len(ps) > 0 {
			id = ps[0].ID
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A local user with the same name as nobody cannot approve an unmapped
	// remote principal's request; only admins can.
	if _, err := b.Resolve(Approver{Name: "u-remote", UID: 1500}, id, true, "once"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("namesake resolve: %v", err)
	}
	if _, err := b.Resolve(admin, id, true, "once"); err != nil {
		t.Fatal(err)
	}
}

func TestGrantsPersistAndRevoke(t *testing.T) {
	file := filepath.Join(t.TempDir(), "grants.json")
	b := newBroker(t, func(o *Options) { o.GrantsFile = file })
	approve := func(scope string) *pep.Grant {
		el := &fakeElicitor{form: true, result: ElicitResult{Action: "accept", Content: map[string]any{"scope": scope}}}
		g, err := b.Approve(context.Background(), el, input(), formAsk)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	durable := approve("24h")
	approve("session")

	// A restart keeps the duration grant, not the session grant; and it
	// applies in a new session.
	b2 := newBroker(t, func(o *Options) { o.GrantsFile = file })
	newSession := alice
	newSession.SessionID = "s9"
	got := b2.Grants(newSession, "fs", "write_file")
	if len(got) != 1 || got[0].ID != durable.ID {
		t.Fatalf("after restart: %+v", got)
	}
	if gs := b2.ListGrants(bobApprover); len(gs) != 0 {
		t.Fatalf("bob sees %+v", gs)
	}
	if gs := b2.ListGrants(aliceApprover); len(gs) != 1 {
		t.Fatalf("alice sees %+v", gs)
	}
	if err := b2.RevokeGrant(bobApprover, durable.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bob revoke: %v", err)
	}
	if err := b2.RevokeGrant(aliceApprover, durable.ID); err != nil {
		t.Fatal(err)
	}
	b3 := newBroker(t, func(o *Options) { o.GrantsFile = file })
	if got := b3.Grants(newSession, "fs", "write_file"); len(got) != 0 {
		t.Fatalf("revoked grant survived restart: %+v", got)
	}
}

func TestExpiredGrantsIgnored(t *testing.T) {
	b := newBroker(t, nil)
	el := &fakeElicitor{form: true, result: ElicitResult{Action: "accept", Content: map[string]any{"scope": "session"}}}
	if _, err := b.Approve(context.Background(), el, input(), formAsk); err != nil {
		t.Fatal(err)
	}
	b.now = func() time.Time { return time.Now().Add(SessionTTL + time.Minute) }
	if got := b.Grants(alice, "fs", "write_file"); len(got) != 0 {
		t.Fatalf("expired grant returned: %+v", got)
	}
}
