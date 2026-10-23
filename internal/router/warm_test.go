package router

import (
	"context"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// With WarmUp, serving starts the shared discovery instances and fills
// their lists, so that the first listing finds them ready; a reload warms
// up the servers it added; servers listed per user are left alone.
func TestWarmUp(t *testing.T) {
	r, l := sharedRouter(t)
	r.WarmUp = true
	r.init()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.startWarmUp(ctx)
	ready := func(name string) bool {
		for _, fi := range l.started(name) {
			if fi.p.Sub == "mcp-discovery" && fi.lists.Load() == 1 {
				return true
			}
		}
		return false
	}
	waitFor(t, func() bool { return ready("fs") })
	if got := instancesFor(l); got["mcp-discovery"] != 1 || got["alice"] != 0 {
		t.Fatalf("after the warm-up: %v", got)
	}
	if len(l.started("git")) != 0 {
		t.Errorf("git (discovery: instance) was started: %v", l.started("git"))
	}
	// The first listing is served from the filled cache.
	c := connect(t, r, alice(), "fs", nil)
	toolNames(t, c, 1)
	if disc := l.started("fs")[0]; disc.lists.Load() != 1 || len(l.started("fs")) != 1 {
		t.Errorf("listing after the warm-up: %d instances, %d lists", len(l.started("fs")), disc.lists.Load())
	}
	// A reload warms up the server it adds.
	next := r.CurrentBackends()
	added := map[string]*config.Backend{}
	for k, v := range next {
		added[k] = v
	}
	added["docs"] = &config.Backend{Name: "docs", Isolation: config.IsolationPrincipal, Discovery: config.DiscoveryShared}
	r.SetBackends(added)
	waitFor(t, func() bool { return ready("docs") })
}

// Without WarmUp nothing starts before the first listing.
func TestNoWarmUp(t *testing.T) {
	r, l := sharedRouter(t)
	r.init()
	r.startWarmUp(context.Background())
	r.SetBackends(map[string]*config.Backend{"fs": r.Backends["fs"],
		"docs": {Name: "docs", Isolation: config.IsolationPrincipal, Discovery: config.DiscoveryShared}})
	time.Sleep(100 * time.Millisecond)
	if len(l.started("fs"))+len(l.started("docs")) != 0 {
		t.Errorf("started without warm-up: %v %v", l.started("fs"), l.started("docs"))
	}
}

// Once the gateway stops (Serve ends), a reload warms nothing up: no
// instance starts after the others stopped.
func TestWarmUpStops(t *testing.T) {
	r, l := sharedRouter(t)
	r.WarmUp = true
	r.init()
	ctx, cancel := context.WithCancel(context.Background())
	r.startWarmUp(ctx)
	cancel()
	r.warm.stop()
	n := len(l.started("fs"))
	r.SetBackends(map[string]*config.Backend{"fs": r.Backends["fs"],
		"docs": {Name: "docs", Isolation: config.IsolationPrincipal, Discovery: config.DiscoveryShared}})
	time.Sleep(100 * time.Millisecond)
	if len(l.started("docs")) != 0 || len(l.started("fs")) != n {
		t.Errorf("warmed up after the stop: fs %d (was %d), docs %d", len(l.started("fs")), n, len(l.started("docs")))
	}
}
