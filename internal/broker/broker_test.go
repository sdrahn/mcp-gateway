package broker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
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

// fakePolicy mimics the shipped approver rules: "self" (by uid) and
// members of wheel.
type fakePolicy struct{}

func (fakePolicy) Bool(_ context.Context, path string, input any) (bool, error) {
	in := input.(map[string]any)
	a := in["approver"].(Approver)
	if slices.Contains(a.Groups, "wheel") {
		return true, nil
	}
	var uid *uint32
	switch path {
	case approvePath:
		uid = in["request"].(map[string]any)["principal"].(principal.Principal).UID
	case manageGrantPath:
		uid = in["grant"].(pep.Grant).UID
	}
	return uid != nil && *uid == a.UID, nil
}

func newBroker(t *testing.T, mod func(*Options)) *Broker {
	t.Helper()
	o := Options{Timeout: 2 * time.Second, Policy: fakePolicy{}, OOB: true, URLTemplate: "https://gw/approvals/{id}"}
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
			if ps := b.ListPending(context.Background(), admin); len(ps) > 0 {
				_, err := b.Resolve(context.Background(), a, ps[0].ID, approve, scope)
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
	if len(b.ListPending(context.Background(), admin)) != 0 {
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
	if len(b.ListPending(context.Background(), admin)) != 0 {
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
		if ps := b.ListPending(context.Background(), admin); len(ps) > 0 {
			id = ps[0].ID
		}
		time.Sleep(5 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("no pending approval")
	}
	if ps := b.ListPending(context.Background(), bobApprover); len(ps) != 0 {
		t.Fatalf("bob sees alice's approvals: %+v", ps)
	}
	if _, err := b.GetPending(context.Background(), bobApprover, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bob get: %v", err)
	}
	if _, err := b.Resolve(context.Background(), bobApprover, id, true, "once"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bob resolve: %v", err)
	}
	if _, err := b.Resolve(context.Background(), aliceApprover, id, true, "forever"); !errors.Is(err, ErrBadScope) {
		t.Fatalf("bad scope: %v", err)
	}
	if ps := b.ListPending(context.Background(), aliceApprover); len(ps) != 1 {
		t.Fatalf("alice sees %d approvals", len(ps))
	}
	if _, err := b.Resolve(context.Background(), aliceApprover, id, true, "once"); err != nil {
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
		if ps := b.ListPending(context.Background(), admin); len(ps) > 0 {
			id = ps[0].ID
		}
		time.Sleep(5 * time.Millisecond)
	}
	// A local user with the same name as nobody cannot approve an unmapped
	// remote principal's request; only admins can.
	if _, err := b.Resolve(context.Background(), Approver{Name: "u-remote", UID: 1500}, id, true, "once"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("namesake resolve: %v", err)
	}
	if _, err := b.Resolve(context.Background(), admin, id, true, "once"); err != nil {
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
	if gs := b2.ListGrants(context.Background(), bobApprover); len(gs) != 0 {
		t.Fatalf("bob sees %+v", gs)
	}
	if gs := b2.ListGrants(context.Background(), aliceApprover); len(gs) != 1 {
		t.Fatalf("alice sees %+v", gs)
	}
	if err := b2.RevokeGrant(context.Background(), bobApprover, durable.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bob revoke: %v", err)
	}
	if err := b2.RevokeGrant(context.Background(), aliceApprover, durable.ID); err != nil {
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

func TestApproverPolicyErrorsDeny(t *testing.T) {
	b := newBroker(t, func(o *Options) { o.Policy = errPolicy{} })
	go func() { _, _ = b.Approve(context.Background(), &fakeElicitor{}, input(), urlAsk) }()
	root := Approver{Name: "root", UID: 0}
	var id string
	for i := 0; i < 200 && id == ""; i++ {
		if ps := b.ListPending(context.Background(), root); len(ps) > 0 {
			id = ps[0].ID
		}
		time.Sleep(5 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("root does not see the pending approval")
	}
	if _, err := b.Resolve(context.Background(), aliceApprover, id, true, "once"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("policy error must deny, got %v", err)
	}
}

func TestSelfOnlyWithoutPolicy(t *testing.T) {
	b := newBroker(t, func(o *Options) { o.Policy = nil })
	go func() { _, _ = b.Approve(context.Background(), &fakeElicitor{}, input(), urlAsk) }()
	var id string
	for i := 0; i < 200 && id == ""; i++ {
		if ps := b.ListPending(context.Background(), aliceApprover); len(ps) > 0 {
			id = ps[0].ID
		}
		time.Sleep(5 * time.Millisecond)
	}
	if id == "" {
		t.Fatal("alice does not see her own approval")
	}
	if ps := b.ListPending(context.Background(), admin); len(ps) != 0 {
		t.Fatal("without policy, group membership must not grant anything")
	}
}

type errPolicy struct{}

func (errPolicy) Bool(context.Context, string, any) (bool, error) {
	return false, errors.New("opa down")
}

type kernelLog struct {
	mu   sync.Mutex
	msgs []string
}

func (k *kernelLog) Send(msg string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.msgs = append(k.msgs, msg)
	return nil
}

func TestAuditEvents(t *testing.T) {
	k := &kernelLog{}
	b := newBroker(t, func(o *Options) { o.Audit = audit.New(io.Discard, audit.Options{Kernel: k}) })

	el := &fakeElicitor{form: true, result: ElicitResult{Action: "accept", Content: map[string]any{"scope": "24h"}}}
	g, err := b.Approve(context.Background(), el, input(), formAsk)
	if err != nil {
		t.Fatal(err)
	}
	el.result = ElicitResult{Action: "decline"}
	if _, err := b.Approve(context.Background(), el, input(), formAsk); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = b.Approve(context.Background(), &fakeElicitor{}, input(), urlAsk) }()
	var id string
	for i := 0; i < 200 && id == ""; i++ {
		if ps := b.ListPending(context.Background(), admin); len(ps) > 0 {
			id = ps[0].ID
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := b.Resolve(context.Background(), admin, id, true, "once"); err != nil {
		t.Fatal(err)
	}
	if err := b.RevokeGrant(context.Background(), admin, g.ID); err != nil {
		t.Fatal(err)
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	want := []string{
		"op=mcp-approval by=alice channel=form id=" + g.ID + " principal=alice scope=24h server=fs target=write_file res=success",
		"op=mcp-approval by=alice channel=form principal=alice server=fs target=write_file res=failed",
		"op=mcp-approval by=carol channel=oob id=" + id + " principal=alice scope=once server=fs target=write_file res=success",
		"op=mcp-grant-revoke by=carol id=" + g.ID + " principal=alice server=fs target=write_file res=success",
	}
	if !slices.Equal(k.msgs, want) {
		t.Fatalf("kernel audit messages:\n%q\nwant\n%q", k.msgs, want)
	}
}

// waitPending waits for the pending approvals to satisfy cond.
func waitPending(t *testing.T, b *Broker, cond func([]Pending) bool) []Pending {
	t.Helper()
	for range 400 {
		if ps := b.ListPending(context.Background(), admin); cond(ps) {
			return ps
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("pending approvals: %+v", b.ListPending(context.Background(), admin))
	return nil
}

// orphaned leaves an oob approval of input() without a waiting call, as a
// client that went away does.
func orphaned(t *testing.T, b *Broker) Pending {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := b.Approve(ctx, &fakeElicitor{}, input(), urlAsk)
		done <- err
	}()
	waitPending(t, b, func(ps []Pending) bool { return len(ps) == 1 && ps[0].Waiting })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("approve: %v", err)
	}
	return waitPending(t, b, func(ps []Pending) bool { return len(ps) == 1 && !ps[0].Waiting })[0]
}

func TestPendingSurvivesCallAndRestart(t *testing.T) {
	dir := t.TempDir()
	files := func(o *Options) {
		o.PendingFile, o.GrantsFile = filepath.Join(dir, "pending.json"), filepath.Join(dir, "grants.json")
	}
	b := newBroker(t, files)
	p := orphaned(t, b)
	if slices.Contains(p.Scopes, "session") || !slices.Contains(p.Scopes, "once") {
		t.Fatalf("scopes of an orphaned approval: %v", p.Scopes)
	}
	st, err := os.Stat(filepath.Join(dir, "pending.json"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("pending file: %v %v", st, err)
	}

	// After a restart the approval is still there and can be decided.
	b2 := newBroker(t, files)
	ps := b2.ListPending(context.Background(), admin)
	if len(ps) != 1 || ps[0].ID != p.ID || ps[0].Waiting || ps[0].Args["path"] != "/home/alice/x" {
		t.Fatalf("restored %+v", ps)
	}
	g, err := b2.Resolve(context.Background(), aliceApprover, p.ID, true, "once")
	if err != nil || g.Scope != "once" {
		t.Fatalf("resolve: %+v %v", g, err)
	}
	if len(b2.ListPending(context.Background(), admin)) != 0 {
		t.Fatal("decided approval still pending")
	}

	// The once grant waits for the next attempt, across restarts, and is
	// used up by it.
	b3 := newBroker(t, files)
	if gs := b3.Grants(alice, "fs", "write_file"); len(gs) != 0 {
		t.Fatalf("once grant matched as a standing grant: %+v", gs)
	}
	once, ok := b3.TakeOnce(alice, "fs", "write_file")
	if !ok || once.ID != g.ID {
		t.Fatalf("take: %+v %v", once, ok)
	}
	if _, ok := b3.TakeOnce(alice, "fs", "write_file"); ok {
		t.Fatal("once grant taken twice")
	}
	b3.ReturnOnce(once)
	if _, ok := b3.TakeOnce(alice, "fs", "write_file"); !ok {
		t.Fatal("returned once grant not available")
	}
	if len(newBroker(t, files).ListPending(context.Background(), admin)) != 0 {
		t.Fatal("pending file still lists the decided approval")
	}
}

func TestRetryTakesOverOrphanedApproval(t *testing.T) {
	b := newBroker(t, nil)
	p := orphaned(t, b)

	in := input()
	in.Principal.SessionID = "s2"
	type result struct {
		g   *pep.Grant
		err error
	}
	done := make(chan result, 1)
	go func() {
		g, err := b.Approve(context.Background(), &fakeElicitor{}, in, urlAsk)
		done <- result{g, err}
	}()
	ps := waitPending(t, b, func(ps []Pending) bool { return len(ps) == 1 && ps[0].Waiting })
	if ps[0].ID != p.ID || !slices.Contains(ps[0].Scopes, "session") {
		t.Fatalf("taken over: %+v (was %s)", ps[0], p.ID)
	}
	if _, err := b.Resolve(context.Background(), aliceApprover, p.ID, true, "session"); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil || r.g == nil || r.g.SessionID != "s2" {
		t.Fatalf("approve: %+v %v", r.g, r.err)
	}

	// Another request (other arguments) does not take it over.
	orphaned(t, b)
	other := input()
	other.Args = map[string]any{"path": "/home/alice/y"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _, _ = b.Approve(ctx, &fakeElicitor{}, other, urlAsk) }()
	waitPending(t, b, func(ps []Pending) bool { return len(ps) == 2 })
}

func TestOrphanedApprovalExpiresAndDeclines(t *testing.T) {
	dir := t.TempDir()
	files := func(o *Options) { o.PendingFile = filepath.Join(dir, "pending.json") }
	b := newBroker(t, files)
	p := orphaned(t, b)

	// Declining it leaves no grant.
	if g, err := b.Resolve(context.Background(), aliceApprover, p.ID, false, ""); err != nil || g != nil {
		t.Fatalf("decline: %+v %v", g, err)
	}
	if _, ok := b.TakeOnce(alice, "fs", "write_file"); ok {
		t.Fatal("declined approval left a grant")
	}

	// Expired ones are dropped, also when loading.
	orphaned(t, b)
	b.now = func() time.Time { return time.Now().Add(time.Hour) }
	if ps := b.ListPending(context.Background(), admin); len(ps) != 0 {
		t.Fatalf("expired approval listed: %+v", ps)
	}
	orphaned(t, newBroker(t, files))
	path := filepath.Join(dir, "pending.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var list []map[string]any
	if err := json.Unmarshal(data, &list); err != nil || len(list) != 1 {
		t.Fatalf("pending file: %s %v", data, err)
	}
	list[0]["expires"] = time.Now().Add(-time.Minute).Format(time.RFC3339Nano)
	data, _ = json.Marshal(list)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if ps := newBroker(t, files).ListPending(context.Background(), admin); len(ps) != 0 {
		t.Fatalf("expired approval restored: %+v", ps)
	}
}

func TestTimeoutDropsApproval(t *testing.T) {
	dir := t.TempDir()
	b := newBroker(t, func(o *Options) {
		o.Timeout = 50 * time.Millisecond
		o.PendingFile = filepath.Join(dir, "pending.json")
	})
	if _, err := b.Approve(context.Background(), &fakeElicitor{}, input(), urlAsk); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
	if len(newBroker(t, func(o *Options) { o.PendingFile = filepath.Join(dir, "pending.json") }).ListPending(context.Background(), admin)) != 0 {
		t.Fatal("timed-out approval persisted")
	}
}
