package router

import (
	"context"
	"encoding/json"
	"slices"
	"sync"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
)

// A modern agent hears about changes on a stream it opens with
// subscriptions/listen (docs/architecture.md, section 5.11.1): the
// changes of lists policy and the server definitions make (as legacy
// sessions are told), the servers' own list changes, and the updates of
// resources it subscribed to, admitted and passed on only while policy
// lets it subscribe to them.

// listenFilter is the notifications field of subscriptions/listen and of
// its acknowledgement.
type listenFilter struct {
	ToolsListChanged      bool     `json:"toolsListChanged,omitempty"`
	PromptsListChanged    bool     `json:"promptsListChanged,omitempty"`
	ResourcesListChanged  bool     `json:"resourcesListChanged,omitempty"`
	ResourceSubscriptions []string `json:"resourceSubscriptions,omitempty"`
}

// agentListen is the stream a listener session serves.
type agentListen struct {
	id     json.RawMessage
	filter listenFilter
	// uris maps a server's resource URI to the URI the agent subscribed
	// to (namespaced on the aggregated endpoint), by server.
	uris map[string]map[string]string
	// end is closed when the gateway ends the stream itself (its server
	// was removed): the agent gets the request's response.
	end chan struct{}

	// Notifications before the acknowledgement wait for it (a server may
	// send an update as soon as it is subscribed).
	mu     sync.Mutex
	acked  bool
	queued []*jsonrpc.Message
}

// listen serves subscriptions/listen: it acknowledges what it honours,
// subscribes at the servers to the resources it admits, and holds the
// stream open until the agent cancels it (no response then) or the
// gateway ends it (a response).
func (s *Session) listen(ctx context.Context, m *jsonrpc.Message) (any, *jsonrpc.Error) {
	var p struct {
		Notifications listenFilter `json:"notifications"`
	}
	if err := json.Unmarshal(m.Params, &p); err != nil {
		return nil, rpcError(jsonrpc.CodeInvalidParams, "invalid params")
	}
	l := &agentListen{id: m.ID, uris: map[string]map[string]string{}, end: make(chan struct{})}
	l.filter.ToolsListChanged = p.Notifications.ToolsListChanged
	l.filter.PromptsListChanged = p.Notifications.PromptsListChanged
	l.filter.ResourcesListChanged = p.Notifications.ResourcesListChanged
	var subscribed []func()
	defer func() {
		for _, unsubscribe := range subscribed {
			unsubscribe()
		}
	}()
	s.mu.Lock()
	s.listening = l
	s.mu.Unlock()
	// Registered at once: changes from now on are queued until the
	// acknowledgement.
	s.r.addListener(s)
	defer s.r.removeListener(s)
	for _, exposed := range p.Notifications.ResourceSubscriptions {
		server, uri, ok := s.endpoint().resolveURI(exposed)
		if !ok || !s.admitSubscription(server, uri) {
			continue
		}
		l.mu.Lock()
		if l.uris[server] == nil {
			l.uris[server] = map[string]string{}
		}
		l.uris[server][uri] = exposed
		l.mu.Unlock()
		unsubscribe, err := s.subscribeAt(ctx, server, uri)
		if err != nil {
			s.log.Info("subscription not set up at the server", "server", server, "err", err)
			l.mu.Lock()
			delete(l.uris[server], uri)
			l.mu.Unlock()
			continue
		}
		subscribed = append(subscribed, unsubscribe)
		l.filter.ResourceSubscriptions = append(l.filter.ResourceSubscriptions, exposed)
	}
	// The acknowledgement comes first; what came meanwhile follows it.
	s.notifyListener("notifications/subscriptions/acknowledged", map[string]any{"notifications": l.filter})
	l.mu.Lock()
	l.acked = true
	queued := l.queued
	l.queued = nil
	l.mu.Unlock()
	for _, n := range queued {
		_ = jsonrpc.WriteRelated(s.client, n, l.id)
	}
	select {
	case <-ctx.Done():
		return nil, nil // the agent cancelled it: no response
	case <-l.end:
		return map[string]any{"_meta": map[string]any{metaSubscriptionID: json.RawMessage(l.id)}}, nil
	}
}

// admitSubscription decides whether the principal may subscribe to a
// server's resource, as resources/subscribe of a session is decided,
// and audits it.
func (s *Session) admitSubscription(server, uri string) bool {
	p := s.snapshotPrincipal()
	decisionID := newDecisionID()
	r := pep.Resource{Server: server, Kind: "resource", Name: uri, Privileged: s.r.privileged(server)}
	dec := pep.Evaluate(s.ctx, s.r.PDP, pep.Input{Principal: p, Action: "resources.subscribe", Resource: r, Context: s.policyContext(decisionID)})
	s.r.Audit.Log(audit.Record{Sub: p.Sub, Action: "resources.subscribe", Server: server, Name: uri,
		Effect: string(dec.Effect), Reason: dec.Reason, DecisionID: decisionID})
	return dec.Effect == pep.Allow
}

// subscribeAt subscribes to a resource at the principal's instance of a
// server: on a modern server's subscription stream (counted per URI,
// undone when the listener ends), with resources/subscribe on a legacy
// one (not undone: the instance is the principal's, and updates reach
// only the listeners that subscribed).
func (s *Session) subscribeAt(ctx context.Context, server, uri string) (func(), error) {
	u, err := s.upstream(ctx, server)
	if err != nil {
		return nil, err
	}
	params, _ := json.Marshal(map[string]string{"uri": uri})
	if u.modern {
		u.subscribe(params, true)
		return func() { u.subscribe(params, false) }, nil
	}
	resp, err := u.request(ctx, s, "resources/subscribe", json.RawMessage(params))
	if err == nil && resp.Error != nil {
		err = resp.Error
	}
	if err != nil {
		return nil, err
	}
	return func() {}, nil
}

// notifyListener writes a notification on the listener's stream, with
// its subscription id.
func (s *Session) notifyListener(method string, params map[string]any) {
	s.mu.Lock()
	l := s.listening
	s.mu.Unlock()
	if l == nil {
		return
	}
	meta, _ := params["_meta"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	meta[metaSubscriptionID] = json.RawMessage(l.id)
	params["_meta"] = meta
	n, err := jsonrpc.NewNotification(method, params)
	if err != nil {
		return
	}
	if method != "notifications/subscriptions/acknowledged" {
		l.mu.Lock()
		if !l.acked {
			l.queued = append(l.queued, n)
			l.mu.Unlock()
			return
		}
		l.mu.Unlock()
	}
	_ = jsonrpc.WriteRelated(s.client, n, l.id)
}

// listChangedOn tells a listener about changed lists, for the kinds it
// asked for.
func (s *Session) listChangedOn(methods ...string) {
	s.mu.Lock()
	l := s.listening
	s.mu.Unlock()
	if l == nil {
		return
	}
	select {
	case <-l.end:
		return // ended by the gateway
	default:
	}
	for _, m := range methods {
		if (m == "notifications/tools/list_changed" && l.filter.ToolsListChanged) ||
			(m == "notifications/prompts/list_changed" && l.filter.PromptsListChanged) ||
			(m == "notifications/resources/list_changed" && l.filter.ResourcesListChanged) {
			s.notifyListener(m, map[string]any{})
		}
	}
}

// resourceUpdated passes a server's resources/updated on to a listener
// that subscribed to the resource, while policy still lets it.
func (s *Session) resourceUpdated(u *upstream, m *jsonrpc.Message) {
	s.mu.Lock()
	l := s.listening
	s.mu.Unlock()
	if l == nil {
		return
	}
	var p map[string]any
	if json.Unmarshal(m.Params, &p) != nil {
		return
	}
	uri, _ := p["uri"].(string)
	l.mu.Lock()
	exposed, ok := l.uris[u.backend.Name][uri]
	l.mu.Unlock()
	if !ok || !s.stillAllowed(u.backend.Name, "resources.subscribe", pep.Resource{Server: u.backend.Name, Kind: "resource", Name: uri}) {
		return
	}
	p["uri"] = exposed
	delete(p, "_meta")
	s.notifyListener(m.Method, p)
}

// endListen ends a listener's stream from the gateway's side.
func (s *Session) endListen() {
	s.mu.Lock()
	l := s.listening
	s.mu.Unlock()
	if l != nil {
		select {
		case <-l.end:
		default:
			close(l.end)
		}
	}
}

// addListener registers a listener for the changes it is told about.
func (r *Router) addListener(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.listeners == nil {
		r.listeners = map[*Session]struct{}{}
	}
	r.listeners[s] = struct{}{}
}

func (r *Router) removeListener(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.listeners, s)
}

// listenersWhere returns the listeners for which keep is true.
func (r *Router) listenersWhere(keep func(*Session) bool) []*Session {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []*Session
	for s := range r.listeners {
		if keep == nil || keep(s) {
			out = append(out, s)
		}
	}
	return out
}

// allLists are the list change notifications.
var allLists = []string{"notifications/tools/list_changed", "notifications/prompts/list_changed", "notifications/resources/list_changed"}

// backendListChanged tells the listeners that a server's list changed:
// those whose endpoint has the server, if the instance is a shared
// discovery one or the listener's principal's.
func (r *Router) backendListChanged(u *upstream, m *jsonrpc.Message) {
	for _, s := range r.listenersWhere(func(s *Session) bool {
		return s.endpoint().backends[u.backend.Name] != nil &&
			(u.internal || u.owner == principalKey(s.snapshotPrincipal()))
	}) {
		if !slices.Contains(allLists, m.Method) {
			continue
		}
		s.listChangedOn(m.Method)
	}
}
