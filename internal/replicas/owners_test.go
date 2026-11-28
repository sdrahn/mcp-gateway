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
