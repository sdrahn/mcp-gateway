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

func sharedBroker(t *testing.T, api *kubetest.Secrets) *Broker {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return newBroker(t, func(o *Options) { o.Shared = &Shared{Context: ctx, Grants: sharedGrants(t, api)} })
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
