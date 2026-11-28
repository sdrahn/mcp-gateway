package broker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/kube/kubetest"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/store"
)

func sharedGrants(t *testing.T, api *kubetest.Secrets) store.Collection {
	t.Helper()
	c, err := store.NewKubernetes(api.Client(), "gw", "grants")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// sharedOptions keeps a broker's state in api, with its own context, as
// the replica gw-a.
func sharedOptions(t *testing.T, api *kubetest.Secrets) func(*Options) {
	t.Helper()
	return replicaOptions(t, api, "gw-a")
}

// replicaOptions is sharedOptions for the replica called replica.
func replicaOptions(t *testing.T, api *kubetest.Secrets, replica string) func(*Options) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	coll := func(name string) store.Collection {
		c, err := store.NewKubernetes(api.Client(), "gw", name)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	return func(o *Options) {
		o.Shared = &Shared{Context: ctx, Grants: coll("grants"), Pending: coll("pending"),
			Notices: coll("notices"), Reviews: coll("reviews"), Requests: coll("requests"), Replica: replica}
	}
}

func sharedBroker(t *testing.T, api *kubetest.Secrets) *Broker {
	t.Helper()
	return newBroker(t, sharedOptions(t, api))
}

// flushed waits until b's state is in the store, as before a restart.
func flushed(t *testing.T, b *Broker) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.Flush(ctx); err != nil {
		t.Fatal(err)
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Two brokers on one store, as two replicas: a duration grant made by
// one counts at the other, a session grant does not leave its broker,
// and a revocation at either ends it at both.
func TestSharedGrants(t *testing.T) {
	api := kubetest.NewSecrets(t)
	a, b := sharedBroker(t, api), sharedBroker(t, api)
	approve := func(scope string) *pep.Grant {
		el := &fakeElicitor{form: true, result: ElicitResult{Action: "accept", Content: map[string]any{"scope": scope}}}
		g, err := a.Approve(context.Background(), el, input(), formAsk)
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	durable := approve("24h")
	approve("session")
	flushed(t, a)
	if n := api.Len("gw"); n != 1 {
		t.Fatalf("%d records, want the duration grant's", n)
	}
	if got := a.Grants(alice, "fs", "write_file"); len(got) != 2 {
		t.Fatalf("at the approving broker: %+v", got)
	}
	newSession := alice
	newSession.SessionID = "s9"
	waitUntil(t, "the grant at the other broker", func() bool {
		got := b.Grants(newSession, "fs", "write_file")
		return len(got) == 1 && got[0].ID == durable.ID
	})
	if gs := b.ListGrants(context.Background(), aliceApprover); len(gs) != 1 {
		t.Fatalf("listed at the other broker: %+v", gs)
	}
	if err := b.RevokeGrant(context.Background(), aliceApprover, durable.ID); err != nil {
		t.Fatal(err)
	}
	if got := b.Grants(newSession, "fs", "write_file"); len(got) != 0 {
		t.Fatalf("revoked, at the revoking broker: %+v", got)
	}
	waitUntil(t, "the revocation at the approving broker", func() bool {
		return len(a.Grants(newSession, "fs", "write_file")) == 0
	})
	if n := api.Len("gw"); n != 0 {
		t.Errorf("%d records after the revocation", n)
	}
}

func openShared(t *testing.T, c store.Collection) *Store {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s, err := OpenSharedStore(ctx, c, time.Now, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func onceGrant(id string) pep.Grant {
	return pep.Grant{ID: id, Sub: alice.Sub, Server: "fs", Tool: "write_file", Scope: "once",
		Expires: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), ApprovedBy: "admin"}
}

// A stored once grant is taken once, whichever replica's call takes it.
func TestSharedOnceTakenOnce(t *testing.T) {
	api := kubetest.NewSecrets(t)
	c := sharedGrants(t, api)
	stores := []*Store{openShared(t, c), openShared(t, c), openShared(t, c)}
	if err := stores[0].Add(onceGrant("g-once")); err != nil {
		t.Fatal(err)
	}
	for _, s := range stores[1:] {
		waitUntil(t, "the grant at every store", func() bool { _, ok := s.Get("g-once"); return ok })
	}
	var taken atomic.Int32
	var wg sync.WaitGroup
	for _, s := range stores {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := s.TakeOnce(alice, "fs", "write_file"); ok {
				taken.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := taken.Load(); n != 1 {
		t.Fatalf("taken %d times", n)
	}
	if n := api.Len("gw"); n != 0 {
		t.Errorf("%d records left", n)
	}
}

// broken fails lists and watches while fail is set, as an API server
// out of reach does.
type broken struct {
	store.Collection
	fail atomic.Bool
}

func (b *broken) List(ctx context.Context) ([]store.Record, string, error) {
	if b.fail.Load() {
		return nil, "", errors.New("no API server")
	}
	return b.Collection.List(ctx)
}

func (b *broken) Watch(ctx context.Context, version string, fn func(store.Event), bookmark func(string)) error {
	if b.fail.Load() {
		return errors.New("no API server")
	}
	return b.Collection.Watch(ctx, version, fn, bookmark)
}

// While the store is not followed, its grants count as absent: the call
// asks rather than being allowed on what may have been revoked. Session
// grants are the gateway's own and still count.
func TestSharedUnsyncedGrantsAbsent(t *testing.T) {
	api := kubetest.NewSecrets(t)
	c := &broken{Collection: sharedGrants(t, api)}
	defer func(d time.Duration) { sharedBackoff = d }(sharedBackoff)
	sharedBackoff = 10 * time.Millisecond
	s := openShared(t, c)
	g := onceGrant("g-24h")
	g.Scope = "duration"
	if err := s.Add(g); err != nil {
		t.Fatal(err)
	}
	session := onceGrant("g-session")
	session.Scope, session.SessionID = "session", alice.SessionID
	if err := s.Add(session); err != nil {
		t.Fatal(err)
	}
	if got := s.Match(alice, "fs", "write_file"); len(got) != 2 {
		t.Fatalf("synced: %+v", got)
	}
	c.fail.Store(true)
	// A watch that got past the check before fail was set may connect
	// only after a first Break.
	waitUntil(t, "the store not followed", func() bool { api.Break(); return !s.shared.Synced() })
	if got := s.Match(alice, "fs", "write_file"); len(got) != 1 || got[0].ID != "g-session" {
		t.Fatalf("not synced: %+v", got)
	}
	c.fail.Store(false)
	waitUntil(t, "the store followed again", func() bool { return len(s.Match(alice, "fs", "write_file")) == 2 })
}

// An expired grant is deleted from the store.
func TestSharedExpiredDropped(t *testing.T) {
	api := kubetest.NewSecrets(t)
	s := openShared(t, sharedGrants(t, api))
	g := onceGrant("g-old")
	g.Scope = "duration"
	if err := s.Add(g); err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if got := s.Match(alice, "fs", "write_file"); len(got) != 0 {
		t.Fatalf("expired matched: %+v", got)
	}
	if got := s.List(); len(got) != 0 {
		t.Fatalf("expired listed: %+v", got)
	}
	waitUntil(t, "the expired grant deleted", func() bool { return api.Len("gw") == 0 })
}

// A pending approval whose call went away is kept in the store: a
// gateway started again (another broker on the store) lists it, decides
// it, and the grant waits for the agent's next attempt.
func TestSharedPendingSurvivesRestart(t *testing.T) {
	api := kubetest.NewSecrets(t)
	b := sharedBroker(t, api)
	p := orphaned(t, b)
	flushed(t, b)
	b2 := sharedBroker(t, api)
	ps := b2.ListPending(context.Background(), admin)
	if len(ps) != 1 || ps[0].ID != p.ID || ps[0].Waiting || ps[0].Args["path"] != "/home/alice/x" {
		t.Fatalf("restored %+v", ps)
	}
	g, err := b2.Resolve(context.Background(), aliceApprover, p.ID, true, "once")
	if err != nil || g.Scope != "once" {
		t.Fatalf("resolve: %+v %v", g, err)
	}
	flushed(t, b2)
	b3 := sharedBroker(t, api)
	if len(b3.ListPending(context.Background(), admin)) != 0 {
		t.Fatal("the decided approval is still in the store")
	}
	if once, ok := b3.TakeOnce(alice, "fs", "write_file"); !ok || once.ID != g.ID {
		t.Fatalf("take: %+v %v", once, ok)
	}
}

// Notices and review items, with their dismissals and verdicts, are kept
// in the store across a restart.
func TestSharedNoticesAndReviews(t *testing.T) {
	api := kubetest.NewSecrets(t)
	opts := func(mod func(*Options)) func(*Options) {
		shared := sharedOptions(t, api)
		return func(o *Options) { shared(o); mod(o) }
	}
	b := newBroker(t, opts(func(o *Options) { o.Policy = noticePolicy{} }))
	n, err := b.PostNotice(t.Context(), rootApprover, demotion())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.DismissNotice(t.Context(), pat, n.ID); err != nil {
		t.Fatal(err)
	}
	flushed(t, b)
	b = newBroker(t, opts(func(o *Options) { o.Policy = noticePolicy{} }))
	if got := b.ListNotices(t.Context(), olga); len(got) != 1 || got[0].ID != n.ID {
		t.Fatalf("notices restored: %+v", got)
	}
	if !b.NoticeDismissed(pat, n.ID) {
		t.Fatal("the dismissal was not kept")
	}

	b = newBroker(t, opts(func(o *Options) { o.Policy = reviewPolicy{} }))
	r := b.AddReview(restart())
	if _, err := b.Judge(t.Context(), opsUser, r.ID, VerdictIncident, "wrong unit", ""); err != nil {
		t.Fatal(err)
	}
	flushed(t, b)
	b = newBroker(t, opts(func(o *Options) { o.Policy = reviewPolicy{} }))
	got, err := b.GetReview(t.Context(), opsUser, r.ID)
	if err != nil || got.Verdict == nil || got.Verdict.Reason != "wrong unit" {
		t.Fatalf("review restored: %+v %v", got, err)
	}
}

// Two replicas on one store: each keeps its own pending approvals without
// deleting the other's, and lists the other's; the approvals of a replica
// that is gone are adopted, and decided where they are now.
func TestSharedPendingReplicas(t *testing.T) {
	api := kubetest.NewSecrets(t)
	defer func(d time.Duration) { sharedBackoff = d }(sharedBackoff)
	sharedBackoff = 10 * time.Millisecond
	a := newBroker(t, replicaOptions(t, api, "gw-a"))
	b := newBroker(t, replicaOptions(t, api, "gw-b"))
	p := orphaned(t, a)
	flushed(t, a)
	// b saves its own (none) after a's: a's record stays.
	b.mu.Lock()
	b.persistPending()
	b.mu.Unlock()
	flushed(t, b)
	// As a wrote it last (its call gone): adopting goes by that version.
	waitUntil(t, "a's approval listed at b", func() bool {
		ps := b.ListPending(context.Background(), admin)
		return len(ps) == 1 && ps[0].ID == p.ID && !ps[0].Waiting
	})
	if got, err := b.GetPending(context.Background(), admin, p.ID); err != nil || got.ID != p.ID {
		t.Fatalf("a's approval at b: %+v %v", got, err)
	}
	// a is gone: b adopts the approval and decides it.
	b.Adopt(context.Background(), func(r string) bool { return r == "gw-b" })
	g, err := b.Resolve(context.Background(), aliceApprover, p.ID, true, "once")
	if err != nil || g.Scope != "once" {
		t.Fatalf("decided at b after adopting it: %+v %v", g, err)
	}
	flushed(t, b)
	if n := len(api.Names("secrets", "gw", "mcp-gateway.io/collection=pending")); n != 0 {
		t.Fatalf("%d pending records left", n)
	}
}

// A notice posted and a review item made on one replica are listed on
// the other.
func TestSharedNoticesReviewsReplicas(t *testing.T) {
	api := kubetest.NewSecrets(t)
	defer func(d time.Duration) { sharedBackoff = d }(sharedBackoff)
	sharedBackoff = 10 * time.Millisecond
	with := func(replica string, pol BoolPolicy) func(*Options) {
		o := replicaOptions(t, api, replica)
		return func(opts *Options) { o(opts); opts.Policy = pol }
	}
	a := newBroker(t, with("gw-a", noticePolicy{}))
	b := newBroker(t, with("gw-b", noticePolicy{}))
	n, err := a.PostNotice(t.Context(), rootApprover, demotion())
	if err != nil {
		t.Fatal(err)
	}
	flushed(t, a)
	waitUntil(t, "a's notice at b", func() bool {
		got := b.ListNotices(t.Context(), olga)
		return len(got) == 1 && got[0].ID == n.ID
	})
	ra := newBroker(t, with("gw-a", reviewPolicy{}))
	rb := newBroker(t, with("gw-b", reviewPolicy{}))
	r := ra.AddReview(restart())
	flushed(t, ra)
	waitUntil(t, "a's review item at b", func() bool {
		got, err := rb.GetReview(t.Context(), opsUser, r.ID)
		return err == nil && got.ID == r.ID && len(rb.ListReviews(t.Context(), opsUser)) == 1
	})
}

// An approval decided on another replica is carried out where its call
// waits: the call gets the grant there (a session grant of its session);
// the first decision wins, wherever made.
func TestSharedDecisionAcrossReplicas(t *testing.T) {
	api := kubetest.NewSecrets(t)
	defer func(d time.Duration) { sharedBackoff = d }(sharedBackoff)
	sharedBackoff = 10 * time.Millisecond
	a := newBroker(t, replicaOptions(t, api, "gw-a"))
	b := newBroker(t, replicaOptions(t, api, "gw-b"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		g   *pep.Grant
		err error
	}
	done := make(chan result, 1)
	go func() {
		ask := urlAsk
		ask.Scopes = []string{"once", "session"}
		g, err := a.Approve(ctx, &fakeElicitor{}, input(), ask)
		done <- result{g, err}
	}()
	var id string
	waitUntil(t, "a's approval listed at b", func() bool {
		ps := b.ListPending(context.Background(), admin)
		if len(ps) == 1 {
			id = ps[0].ID
		}
		return len(ps) == 1
	})
	g, err := b.Resolve(context.Background(), aliceApprover, id, true, "session")
	if err != nil || g == nil || g.Scope != "session" || g.ApprovedBy != "alice" {
		t.Fatalf("decided at b: %+v %v", g, err)
	}
	// A second decision, at a or b, is too late.
	if _, err := a.Resolve(context.Background(), aliceApprover, id, false, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a second decision at a: %v", err)
	}
	select {
	case r := <-done:
		if r.err != nil || r.g == nil || r.g.Scope != "session" || r.g.SessionID != alice.SessionID || r.g.ApprovedBy != "alice" {
			t.Fatalf("the waiting call got %+v %v", r.g, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the call at a was not woken")
	}
	if got := a.Grants(alice, "fs", "write_file"); len(got) != 1 || got[0].Scope != "session" {
		t.Fatalf("the session grant at a: %+v", got)
	}
}

// A notice's dismissal and a review item's verdict made on another
// replica are recorded by the replica that holds them.
func TestSharedDismissalVerdictAcrossReplicas(t *testing.T) {
	api := kubetest.NewSecrets(t)
	defer func(d time.Duration) { sharedBackoff = d }(sharedBackoff)
	sharedBackoff = 10 * time.Millisecond
	with := func(replica string, pol BoolPolicy) func(*Options) {
		o := replicaOptions(t, api, replica)
		return func(opts *Options) { o(opts); opts.Policy = pol }
	}
	a := newBroker(t, with("gw-a", noticePolicy{}))
	b := newBroker(t, with("gw-b", noticePolicy{}))
	n, err := a.PostNotice(t.Context(), rootApprover, demotion())
	if err != nil {
		t.Fatal(err)
	}
	flushed(t, a)
	waitUntil(t, "a's notice at b", func() bool { return len(b.ListNotices(t.Context(), pat)) == 1 })
	if err := b.DismissNotice(t.Context(), pat, n.ID); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the dismissal at a", func() bool { return a.NoticeDismissed(pat, n.ID) })
	waitUntil(t, "the dismissal seen at b", func() bool { return len(b.ListNotices(t.Context(), pat)) == 0 })

	ra := newBroker(t, with("gw-a", reviewPolicy{}))
	rb := newBroker(t, with("gw-b", reviewPolicy{}))
	r := ra.AddReview(restart())
	flushed(t, ra)
	waitUntil(t, "a's review item at b", func() bool { _, err := rb.GetReview(t.Context(), opsUser, r.ID); return err == nil })
	got, err := rb.Judge(t.Context(), opsUser, r.ID, VerdictIncident, "wrong unit", "")
	if err != nil || got.Verdict == nil || got.Verdict.Reason != "wrong unit" {
		t.Fatalf("judged at b: %+v %v", got, err)
	}
	waitUntil(t, "the verdict at a", func() bool {
		got, err := ra.GetReview(t.Context(), opsUser, r.ID)
		return err == nil && got.Verdict != nil && got.Verdict.Reason == "wrong unit"
	})
}
