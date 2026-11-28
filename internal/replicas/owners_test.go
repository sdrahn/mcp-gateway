package replicas

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/kube/kubetest"
)

func owners(api *kubetest.Secrets, m *Members, c *clock) *Owners {
	return &Owners{Client: api.Client(), Namespace: "gw", Members: m, Idle: time.Minute, Now: c.now}
}

// The first replica a principal's request reaches takes its Lease; the
// others see that replica as the owner; when it is gone, the next takes
// it over.
func TestOwners(t *testing.T) {
	api := kubetest.NewSecrets(t)
	c := &clock{t: time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)}
	ma, mb := member(api, "gw-a", c), member(api, "gw-b", c)
	ctx := context.Background()
	for _, m := range []*Members{ma, mb} {
		if err := m.Join(ctx); err != nil {
			t.Fatal(err)
		}
	}
	_ = ma.refresh(ctx)
	oa, ob := owners(api, ma, c), owners(api, mb, c)
	if got, err := oa.Owner(ctx, "http\x00idp\x00alice"); err != nil || got != "gw-a" {
		t.Fatalf("a's first: %q %v", got, err)
	}
	if got, err := ob.Owner(ctx, "http\x00idp\x00alice"); err != nil || got != "gw-a" {
		t.Fatalf("at b: %q %v", got, err)
	}
	if got, _ := ob.Owner(ctx, "http\x00idp\x00bob"); got != "gw-b" {
		t.Fatalf("bob at b: %q", got)
	}
	if n := len(api.Names("leases", "gw", "mcp-gateway.io/role=owner")); n != 2 {
		t.Fatalf("%d owner Leases", n)
	}
	// a goes (its replica Lease given up): b takes alice over.
	ma.leave()
	_ = mb.refresh(ctx)
	c.add(foreignTTL)
	if got, err := ob.Owner(ctx, "http\x00idp\x00alice"); err != nil || got != "gw-b" {
		t.Fatalf("after a went: %q %v", got, err)
	}
	// a's next renewal finds its Lease taken, and forgets alice.
	oa.renew(ctx)
	if len(oa.Held()) != 0 {
		t.Fatalf("a still holds %v", oa.Held())
	}
}

// Two replicas taking one principal at once: one of them gets it, and
// both agree.
func TestOwnersRace(t *testing.T) {
	api := kubetest.NewSecrets(t)
	c := &clock{t: time.Now()}
	var os []*Owners
	for _, name := range []string{"gw-a", "gw-b", "gw-c"} {
		m := member(api, name, c)
		if err := m.Join(context.Background()); err != nil {
			t.Fatal(err)
		}
		os = append(os, owners(api, m, c))
	}
	for _, o := range os {
		_ = o.Members.refresh(context.Background())
	}
	got := make([]string, len(os))
	var wg sync.WaitGroup
	for i, o := range os {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], _ = o.Owner(context.Background(), "carol")
		}()
	}
	wg.Wait()
	if got[0] == "" || got[0] != got[1] || got[1] != got[2] {
		t.Fatalf("owners %v", got)
	}
}

// A principal not busy and not used within Idle is given up; a busy one
// is kept; at the end all are given up.
func TestOwnersRenewRelease(t *testing.T) {
	api := kubetest.NewSecrets(t)
	c := &clock{t: time.Now()}
	m := member(api, "gw-a", c)
	ctx := context.Background()
	if err := m.Join(ctx); err != nil {
		t.Fatal(err)
	}
	o := owners(api, m, c)
	o.Busy = func() map[string]bool { return map[string]bool{"busy": true} }
	for _, k := range []string{"busy", "idle", "used"} {
		if _, err := o.Owner(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	c.add(50 * time.Second)
	_, _ = o.Owner(ctx, "used")
	c.add(20 * time.Second)
	o.renew(ctx)
	held := map[string]bool{}
	for _, k := range o.Held() {
		held[k] = true
	}
	if !held["busy"] || !held["used"] || held["idle"] {
		t.Fatalf("held %v", held)
	}
	if n := len(api.Names("leases", "gw", "mcp-gateway.io/role=owner")); n != 2 {
		t.Fatalf("%d owner Leases after the renewal", n)
	}
	o.releaseAll()
	if n := len(api.Names("leases", "gw", "mcp-gateway.io/role=owner")); n != 0 || len(o.Held()) != 0 {
		t.Fatalf("%d owner Leases after giving up", n)
	}
}

// A draining replica takes no new principals: it names one that takes
// them, the same for a principal on each draining replica, which takes it
// when the request reaches it; the principals it holds that are not busy
// are given up at once, the busy ones once they are done, and the others
// see it draining.
func TestDrain(t *testing.T) {
	api := kubetest.NewSecrets(t)
	c := &clock{t: time.Now()}
	ma, mb := member(api, "gw-a", c), member(api, "gw-b", c)
	ctx := context.Background()
	for _, m := range []*Members{ma, mb} {
		if err := m.Join(ctx); err != nil {
			t.Fatal(err)
		}
	}
	_ = ma.refresh(ctx)
	var mu sync.Mutex
	busy := map[string]bool{"busy": true}
	oa, ob := owners(api, ma, c), owners(api, mb, c)
	oa.Busy = func() map[string]bool {
		mu.Lock()
		defer mu.Unlock()
		return map[string]bool{"busy": busy["busy"]}
	}
	for _, k := range []string{"busy", "idle"} {
		if got, err := oa.Owner(ctx, k); err != nil || got != "gw-a" {
			t.Fatalf("%s: %q %v", k, got, err)
		}
	}
	if err := ma.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	_ = mb.refresh(ctx)
	if !ma.Draining() || mb.Draining() || len(mb.Takers()) != 0 || len(ma.Takers()) != 1 {
		t.Fatalf("draining: a %v b %v, takers at b %v, at a %v", ma.Draining(), mb.Draining(), mb.Takers(), ma.Takers())
	}
	if !mb.Live()["gw-a"].Draining {
		t.Error("b does not see a draining")
	}
	// A new principal: b's, not taken here.
	if got, err := oa.Owner(ctx, "new"); err != nil || got != "gw-b" {
		t.Fatalf("new at a: %q %v", got, err)
	}
	if got, err := ob.Owner(ctx, "new"); err != nil || got != "gw-b" {
		t.Fatalf("new at b: %q %v", got, err)
	}
	// The busy one is kept while busy; it is served here meanwhile.
	done := make(chan struct{})
	go func() { oa.Drain(ctx); close(done) }()
	waitFor(t, "idle given up", func() bool { return len(oa.Held()) == 1 })
	if got, _ := oa.Owner(ctx, "busy"); got != "gw-a" {
		t.Errorf("busy while draining: %q", got)
	}
	mu.Lock()
	busy["busy"] = false
	mu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("drain did not end")
	}
	if n := len(api.Names("leases", "gw", "mcp-gateway.io/role=owner")); n != 1 {
		t.Errorf("%d owner Leases after draining (b's new one only)", n)
	}
	// Alone and draining, a replica serves what comes rather than none.
	_ = mb.Drain(ctx)
	_ = ma.refresh(ctx)
	if got, err := oa.Owner(ctx, "late"); err != nil || got != "gw-a" {
		t.Errorf("late with every replica draining: %q %v", got, err)
	}
}

// Drain ends at its deadline with a principal still busy.
func TestDrainTimeout(t *testing.T) {
	api := kubetest.NewSecrets(t)
	c := &clock{t: time.Now()}
	m := member(api, "gw-a", c)
	ctx := context.Background()
	if err := m.Join(ctx); err != nil {
		t.Fatal(err)
	}
	o := owners(api, m, c)
	o.Busy = func() map[string]bool { return map[string]bool{"busy": true} }
	if _, err := o.Owner(ctx, "busy"); err != nil {
		t.Fatal(err)
	}
	dctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	start := time.Now()
	o.Drain(dctx)
	if d := time.Since(start); d < time.Second || d > 4*time.Second || len(o.Held()) != 1 {
		t.Errorf("drain took %s, holds %v", d, o.Held())
	}
}

// A principal with an instance only (Busy, not Kept) is given up at
// once: its instance ends with the replica either way.
func TestDrainKept(t *testing.T) {
	api := kubetest.NewSecrets(t)
	c := &clock{t: time.Now()}
	m := member(api, "gw-a", c)
	ctx := context.Background()
	if err := m.Join(ctx); err != nil {
		t.Fatal(err)
	}
	o := owners(api, m, c)
	o.Busy = func() map[string]bool { return map[string]bool{"instance": true, "session": true} }
	o.Kept = func() map[string]bool { return map[string]bool{"session": true} }
	for _, k := range []string{"instance", "session"} {
		if _, err := o.Owner(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	dctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	o.Drain(dctx)
	if held := o.Held(); len(held) != 1 || held[0] != "session" {
		t.Errorf("held after the drain: %v, want the session's only", held)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A replica that came after another's last list holds a principal: the
// other lists again and sees it as the owner, rather than take the
// principal over as from a replica that is gone (two owners, sessions on
// one that requests then miss on the other).
func TestOwnerNewReplica(t *testing.T) {
	api := kubetest.NewSecrets(t)
	c := &clock{t: time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)}
	ma := member(api, "gw-a", c)
	ctx := context.Background()
	if err := ma.Join(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ma.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	// gw-b joins after a's list, and takes the principal.
	mb := member(api, "gw-b", c)
	if err := mb.Join(ctx); err != nil {
		t.Fatal(err)
	}
	_ = mb.refresh(ctx)
	ob := owners(api, mb, c)
	if got, err := ob.Owner(ctx, "p"); err != nil || got != "gw-b" {
		t.Fatalf("at b: %q %v", got, err)
	}
	if ma.IsLive("gw-b") {
		t.Fatal("a already sees b")
	}
	oa := owners(api, ma, c)
	if got, err := oa.Owner(ctx, "p"); err != nil || got != "gw-b" {
		t.Fatalf("at a: %q %v (a took b's principal over)", got, err)
	}
	if len(oa.Held()) != 0 {
		t.Errorf("a holds %v", oa.Held())
	}
}
