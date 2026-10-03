package router

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Shared discovery (docs/architecture.md, section 7.3): for backends with
// discovery: shared, tool, prompt and resource template lists and the
// initialize result come from one gateway-owned instance per backend that
// runs without any user's identity (a dynamic user under systemd; home
// "/"; it only ever gets list requests). Lists are cached until the
// backend reports a change (*/list_changed, from any of its instances) or
// the discovery instance stops (idle timeout). Listing thus neither starts
// an instance for every user nor serves one user's view to another. What
// is visible stays per principal: policy filters the cached lists.
// resources/list is user data and always comes from the user's instance.

// discoveryPrincipal is the identity shared discovery instances run for.
var discoveryPrincipal = principal.Discovery

// sharedMethods are the list methods served from shared discovery.
var sharedMethods = map[string]bool{"tools/list": true, "prompts/list": true, "resources/templates/list": true}

// invalidates maps list_changed notifications to the lists they affect.
var invalidates = map[string][]string{
	"notifications/tools/list_changed":     {"tools/list"},
	"notifications/prompts/list_changed":   {"prompts/list"},
	"notifications/resources/list_changed": {"resources/templates/list"},
}

type discoveryCache struct {
	mu      sync.Mutex
	entries map[string]*listEntry // by backend "\x00" method
}

type listEntry struct {
	u     *upstream // the discovery instance the list came from
	items []cachedItem
	ready chan struct{} // closed when items (or err) are set
	err   error
}

type cachedItem struct {
	name string
	raw  json.RawMessage
}

func cacheKey(backend, method string) string { return backend + "\x00" + method }

// sharedList returns backend b's list for method from the cache, fetching
// it from the discovery instance if needed.
func (r *Router) sharedList(ctx context.Context, b *config.Backend, method string, spec listSpec) ([]listItem, error) {
	key := cacheKey(b.Name, method)
	for {
		r.discovery.mu.Lock()
		if r.discovery.entries == nil {
			r.discovery.entries = map[string]*listEntry{}
		}
		e := r.discovery.entries[key]
		if e == nil {
			e = &listEntry{ready: make(chan struct{})}
			r.discovery.entries[key] = e
			r.discovery.mu.Unlock()
			r.fillList(ctx, b, method, spec, e)
		} else {
			r.discovery.mu.Unlock()
		}
		select {
		case <-e.ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if e.err != nil {
			return nil, e.err
		}
		if e.u.isClosed() {
			r.dropEntry(key, e) // the discovery instance stopped: fetch again
			continue
		}
		items := make([]listItem, 0, len(e.items))
		for _, it := range e.items {
			var raw map[string]json.RawMessage
			if json.Unmarshal(it.raw, &raw) == nil {
				items = append(items, listItem{server: b.Name, name: it.name, raw: raw})
			}
		}
		return items, nil
	}
}

func (r *Router) fillList(ctx context.Context, b *config.Backend, method string, spec listSpec, e *listEntry) {
	defer close(e.ready)
	u, release, err := r.pool.acquire(ctx, b, discoveryPrincipal)
	if err != nil {
		e.err = err
		r.dropEntry(cacheKey(b.Name, method), e)
		return
	}
	defer release()
	items, err := fetchPages(ctx, u, nil, b.Name, method, spec)
	if err != nil {
		e.err = err
		r.dropEntry(cacheKey(b.Name, method), e)
		return
	}
	e.u = u
	for _, it := range items {
		raw, err := json.Marshal(it.raw)
		if err == nil {
			e.items = append(e.items, cachedItem{name: it.name, raw: raw})
		}
	}
}

func (r *Router) dropEntry(key string, e *listEntry) {
	r.discovery.mu.Lock()
	defer r.discovery.mu.Unlock()
	if r.discovery.entries[key] == e {
		delete(r.discovery.entries, key)
	}
}

// sharedInit returns the initialize result of backend b's discovery
// instance.
func (r *Router) sharedInit(ctx context.Context, b *config.Backend) (initResult, error) {
	u, release, err := r.pool.acquire(ctx, b, discoveryPrincipal)
	if err != nil {
		return initResult{}, err
	}
	defer release()
	return u.init, nil
}

// listChanged handles a */list_changed notification from an instance of a
// backend: cached lists of that backend are dropped, and sessions that
// see the backend through shared discovery and did not get the
// notification from their own instance are told as well.
func (r *Router) listChanged(u *upstream, m *jsonrpc.Message) {
	methods := invalidates[m.Method]
	r.discovery.mu.Lock()
	for _, method := range methods {
		delete(r.discovery.entries, cacheKey(u.backend.Name, method))
	}
	r.discovery.mu.Unlock()
	if len(methods) == 0 || (!u.internal && m.Method == "notifications/resources/list_changed") {
		return // another user's resources are not this session's concern
	}
	r.mu.Lock()
	var tell []*Session
	for s := range r.sessions {
		if b := s.endpoint().backends[u.backend.Name]; b != nil && b.Discovery == config.DiscoveryShared && !u.isAttached(s) {
			tell = append(tell, s)
		}
	}
	r.mu.Unlock()
	for _, s := range tell {
		s.upstreamNotification(u, m)
	}
}
