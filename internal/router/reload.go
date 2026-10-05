package router

import (
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// backends returns the current server definitions. They are r.Backends
// until SetBackends replaces them; the map is never changed in place.
func (r *Router) backends() map[string]*config.Backend {
	r.init()
	return *r.registry.Load()
}

// CurrentBackends returns the server definitions in force.
func (r *Router) CurrentBackends() map[string]*config.Backend { return r.backends() }

// BackendChanges names the servers a SetBackends added, changed and
// removed.
type BackendChanges struct {
	Added, Changed, Removed []string
}

// Empty reports whether nothing changed.
func (c BackendChanges) Empty() bool {
	return len(c.Added)+len(c.Changed)+len(c.Removed) == 0
}

// SetBackends puts new server definitions in force, validated by the
// caller (config.LoadBackends). Sessions see the new set at once: servers
// added appear, removed ones disappear. A session's next call to a
// changed server starts an instance from the new definition; the old
// instance runs until no session uses it and no call is in flight on
// it. Instances of removed servers stop once their calls in flight are
// answered. Cached discovery lists of both are fetched anew, and
// principals' tokens that no longer fit (SignIns.DefinitionChanged) go.
// Every session is told that its lists changed.
func (r *Router) SetBackends(next map[string]*config.Backend) BackendChanges {
	r.init()
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()
	r.lastChange.Store(time.Now())
	prev := *r.registry.Load()
	next = maps.Clone(next)
	var ch BackendChanges
	for _, name := range slices.Sorted(maps.Keys(next)) {
		old, ok := prev[name]
		switch {
		case !ok:
			ch.Added = append(ch.Added, name)
		case !sameDefinition(old, next[name]):
			ch.Changed = append(ch.Changed, name)
		default:
			next[name] = old // unchanged: keep the definition sessions use
		}
	}
	for _, name := range slices.Sorted(maps.Keys(prev)) {
		if _, ok := next[name]; !ok {
			ch.Removed = append(ch.Removed, name)
		}
	}
	if ch.Empty() {
		return ch
	}
	r.registry.Store(&next)

	r.mu.Lock()
	sessions := make([]*Session, 0, len(r.sessions))
	for s := range r.sessions {
		sessions = append(sessions, s)
	}
	r.mu.Unlock()
	sessions = append(sessions, r.listenersWhere(nil)...)
	for _, s := range sessions {
		ep := s.endpoint()
		var nep endpoint
		if ep.aggregated {
			nep = aggregatedEndpoint(next)
		} else if b, ok := next[ep.order[0]]; ok {
			nep = singleEndpoint(b)
		} else {
			// The session's server went away: its calls fail as for an
			// unknown server, a listener's stream ends.
			nep = endpoint{backends: map[string]*config.Backend{}, order: ep.order}
			s.endListen()
		}
		s.ep.Store(&nep)
	}
	for _, name := range ch.Removed {
		r.pool.retire(name, true)
		r.forgetDiscovery(name)
		if r.SignIns != nil {
			r.SignIns.DefinitionChanged(prev[name], nil)
		}
	}
	for _, name := range ch.Changed {
		r.pool.retire(name, false)
		r.forgetDiscovery(name)
		if r.SignIns != nil {
			r.SignIns.DefinitionChanged(prev[name], next[name])
		}
	}
	r.Log.Info("server definitions changed; notifying sessions", "added", ch.Added, "changed", ch.Changed,
		"removed", ch.Removed, "sessions", len(sessions))
	for _, s := range sessions {
		s.listChanged()
	}
	return ch
}

// sameDefinition reports whether two definitions start the same
// instances (warnings aside).
func sameDefinition(a, b *config.Backend) bool {
	x, y := *a, *b
	x.Warnings, y.Warnings = nil, nil
	return reflect.DeepEqual(x, y)
}

// forgetDiscovery drops the cached discovery lists of server.
func (r *Router) forgetDiscovery(server string) {
	r.discovery.mu.Lock()
	defer r.discovery.mu.Unlock()
	for key := range r.discovery.entries {
		if strings.HasPrefix(key, server+"\x00") {
			delete(r.discovery.entries, key)
		}
	}
}
