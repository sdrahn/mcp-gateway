package router

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// sharedRouter is testRouter with shared discovery for fs.
func sharedRouter(t *testing.T) (*Router, *fakeLauncher) {
	t.Helper()
	r, l := testRouter(t, time.Hour)
	for _, b := range r.Backends {
		b.Discovery = config.DiscoveryInstance
	}
	r.Backends["fs"].Discovery = config.DiscoveryShared
	return r, l
}

func bob() principal.Principal {
	p := alice()
	uid := uint32(1002)
	p.Sub, p.UID = "bob", &uid
	return p
}

// instancesFor lists the started fs instances by principal.
func instancesFor(l *fakeLauncher) map[string]int {
	out := map[string]int{}
	for _, fi := range l.started("fs") {
		out[fi.p.Sub]++
	}
	return out
}

func toolNames(t *testing.T, c *client, id int) string {
	t.Helper()
	m := c.roundTrip(id, "tools/list", map[string]any{})
	if m.Error != nil {
		t.Fatalf("tools/list: %+v", m.Error)
	}
	return string(m.Result)
}

func TestSharedDiscovery(t *testing.T) {
	r, l := sharedRouter(t)
	ca := connect(t, r, alice(), "fs", nil)
	cb := connect(t, r, bob(), "fs", nil)
	// Connecting did not start any user's instance.
	if got := instancesFor(l); got["alice"] != 0 || got["bob"] != 0 || got["mcp-discovery"] != 1 {
		t.Fatalf("after initialize: %v", got)
	}

	a := toolNames(t, ca, 1)
	b := toolNames(t, cb, 1)
	if !strings.Contains(a, "read_file") || a != b {
		t.Fatalf("lists differ or lack tools:\n%s\n%s", a, b)
	}
	disc := l.started("fs")[0]
	if disc.p.Transport != principal.TransportInternal || disc.lists.Load() != 1 {
		t.Fatalf("discovery instance %+v served %d lists", disc.p, disc.lists.Load())
	}
	if got := instancesFor(l); got["alice"] != 0 || got["bob"] != 0 {
		t.Fatalf("listing started user instances: %v", got)
	}

	// A call runs on the user's own instance.
	if text, isErr := toolText(t, ca.roundTrip(2, "tools/call", map[string]any{"name": "read_file"})); isErr || text != "fs did read_file" {
		t.Fatalf("call: %q %v", text, isErr)
	}
	if got := instancesFor(l); got["alice"] != 1 {
		t.Fatalf("call did not start alice's instance: %v", got)
	}

	// A change reported by the backend drops the cache and reaches both
	// sessions.
	disc.notify("notifications/tools/list_changed")
	for _, c := range []*client{ca, cb} {
		if m := c.read(); m.Method != "notifications/tools/list_changed" {
			t.Fatalf("notification %+v", m)
		}
	}
	toolNames(t, cb, 3)
	if n := disc.lists.Load(); n != 2 {
		t.Fatalf("list not fetched again after the change: %d", n)
	}

	// When the discovery instance stops (idle timeout), the next listing
	// starts a new one.
	if !r.StopInstance(disc.id) {
		t.Fatal("discovery instance not running")
	}
	<-disc.closed
	toolNames(t, ca, 4)
	if got := instancesFor(l); got["mcp-discovery"] != 2 {
		t.Fatalf("instances after the discovery instance stopped: %v", got)
	}
}

func TestSharedDiscoveryFallsBack(t *testing.T) {
	r, l := sharedRouter(t)
	l.failFor = func(p principal.Principal) error {
		if p.Transport == principal.TransportInternal {
			return errors.New("cannot run without a user")
		}
		return nil
	}
	c := connect(t, r, alice(), "fs", nil)
	if names := toolNames(t, c, 1); !strings.Contains(names, "read_file") {
		t.Fatalf("tools %s", names)
	}
	if got := instancesFor(l); got["alice"] != 1 {
		t.Fatalf("fallback did not use alice's instance: %v", got)
	}
}

func TestSetLevelStartsNoInstances(t *testing.T) {
	r, l := sharedRouter(t)
	c := connect(t, r, alice(), "", nil) // aggregated
	if m := c.roundTrip(1, "logging/setLevel", map[string]any{"level": "debug"}); m.Error != nil {
		t.Fatalf("setLevel: %+v", m.Error)
	}
	// The overview in the instructions may have started discovery
	// instances at initialize; none of alice's.
	for _, name := range []string{"fs", "git", "tmp"} {
		for _, fi := range l.started(name) {
			if fi.p.Sub != discoveryPrincipal.Sub {
				t.Fatalf("setLevel started a %s instance for %s", name, fi.p.Sub)
			}
		}
	}
}

// resources/list comes from the principal's own instances, but only of
// servers that offer resources, as shared discovery tells: a client that
// lists resources when it connects does not start every server for its
// user.
func TestResourcesListStartsOnlyServersWithResources(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	for _, b := range r.Backends {
		b.Discovery = config.DiscoveryShared
	}
	r.Backends["toolsonly"] = &config.Backend{Name: "toolsonly", Isolation: config.IsolationPrincipal, Discovery: config.DiscoveryShared}
	c := connect(t, r, alice(), "", nil)
	if m := c.roundTrip(1, "resources/list", map[string]any{}); m.Error != nil {
		t.Fatalf("resources/list: %+v", m.Error)
	}
	for _, fi := range l.started("toolsonly") {
		if fi.p.Sub != "mcp-discovery" {
			t.Errorf("an instance of a server without resources started for %s", fi.p.Sub)
		}
	}
	var forAlice int
	for _, fi := range l.started("fs") {
		if fi.p.Sub == "alice" {
			forAlice++
		}
	}
	if forAlice != 1 {
		t.Errorf("fs (with resources) instances for alice: %d", forAlice)
	}
	// Its tools are still listed, and a call starts alice's instance.
	if got := toolNames(t, c, 2); !strings.Contains(got, "toolsonly__read_file") {
		t.Errorf("tools: %s", got)
	}
}
