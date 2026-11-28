package replicas

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/kube"
	"github.com/sdrahn/mcp-gateway/internal/kube/kubetest"
)

// clock is a time tests move.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func member(api *kubetest.Secrets, name string, c *clock) *Members {
	return &Members{Client: api.Client(), Namespace: "gw", Name: name, Address: name + ":8444", Now: c.now}
}

// Two replicas see each other; one that goes (its Lease given up) is not
// live any more; one whose Lease ran out is not either.
func TestMembers(t *testing.T) {
	api := kubetest.NewSecrets(t)
	c := &clock{t: time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)}
	a, b := member(api, "gw-a", c), member(api, "gw-b", c)
	ctx := context.Background()
	if err := a.Join(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Join(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	live := a.Live()
	if len(live) != 2 || live["gw-b"].Address != "gw-b:8444" || !a.IsLive("gw-b") {
		t.Fatalf("live at a: %+v", live)
	}
	if n := api.LenOf("leases", "gw"); n != 2 {
		t.Fatalf("%d Leases", n)
	}

	// b renews, a does not: past the duration, a is gone for b, and b
	// still sees itself.
	c.add(10 * time.Second)
	if err := b.renew(ctx); err != nil {
		t.Fatal(err)
	}
	c.add(10 * time.Second)
	if err := b.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if b.IsLive("gw-a") || !b.IsLive("gw-b") || len(b.Live()) != 1 {
		t.Fatalf("after a's Lease ran out: %+v", b.Live())
	}
	// a renews again: back.
	if err := a.renew(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if !b.IsLive("gw-a") {
		t.Fatal("a renewed, not live")
	}
	// a gives its Lease up.
	a.leave()
	if err := b.refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if b.IsLive("gw-a") || api.LenOf("leases", "gw") != 1 {
		t.Fatalf("after a left: %+v", b.Live())
	}
}

// A replica that starts again under the name of an earlier run's takes
// its Lease; one whose Lease was written under it takes it back.
func TestMembersTakeOver(t *testing.T) {
	api := kubetest.NewSecrets(t)
	c := &clock{t: time.Now()}
	old := member(api, "gw-a", c)
	ctx := context.Background()
	if err := old.Join(ctx); err != nil {
		t.Fatal(err)
	}
	again := member(api, "gw-a", c)
	again.Address = "10.0.0.9:8444"
	if err := again.Join(ctx); err != nil {
		t.Fatal(err)
	}
	if got := again.Live()["gw-a"].Address; got != "10.0.0.9:8444" {
		t.Fatalf("address %q", got)
	}
	// The old one's next renewal finds the Lease changed and takes it
	// back (the same name is the same replica).
	if err := old.renew(ctx); err != nil {
		t.Fatal(err)
	}
	if n := api.LenOf("leases", "gw"); n != 1 {
		t.Fatalf("%d Leases", n)
	}
}

// Run renews and lists, calls OnChange when a replica comes or goes, and
// gives the Lease up at the end.
func TestMembersRun(t *testing.T) {
	api := kubetest.NewSecrets(t)
	var changes atomic.Int32
	a := &Members{Client: api.Client(), Namespace: "gw", Name: "gw-a", Duration: 3 * time.Second,
		OnChange: func() { changes.Add(1) }}
	ctx, cancel := context.WithCancel(context.Background())
	if err := a.Join(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	now := kube.NewMicroTime(time.Now())
	api.PutObject("leases", "gw", kube.Lease{APIVersion: "coordination.k8s.io/v1", Kind: "Lease",
		Metadata: kube.ObjectMeta{Name: "mcp-gateway-replica-gw-b", Labels: map[string]string{ManagedByLabel: ManagedBy, RoleLabel: RoleReplica}},
		Spec:     kube.LeaseSpec{HolderIdentity: "gw-b", LeaseDurationSeconds: 60, RenewTime: now}})
	deadline := time.Now().Add(5 * time.Second)
	for !a.IsLive("gw-b") {
		if time.Now().After(deadline) {
			t.Fatal("b not seen")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if changes.Load() < 2 {
		t.Errorf("%d changes", changes.Load())
	}
	if names := api.Names("leases", "gw", ""); len(names) != 1 || names[0] != "mcp-gateway-replica-gw-b" {
		t.Errorf("Leases after a stopped: %v", names)
	}
}
