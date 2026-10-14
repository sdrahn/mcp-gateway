package router

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// The clients using the gateway, as the control API lists them
// (docs/architecture.md, section 11, step 34): the sessions, and the
// agents of 2026-07-28, which have none, as last seen.

// agentSeenFor is how long an agent of 2026-07-28 is listed after its
// last request.
const agentSeenFor = time.Hour

// SessionInfo is a client of the gateway: a session (Kind "session") or
// an agent of 2026-07-28 as last seen (Kind "agent").
type SessionInfo struct {
	ID        string              `json:"id"`
	Kind      string              `json:"kind"`
	Sub       string              `json:"sub"`
	Issuer    string              `json:"iss,omitempty"`
	UID       *uint32             `json:"uid,omitempty"`
	Transport principal.Transport `json:"transport"`
	// Endpoint is the server, or "all" for the aggregated endpoint, whose
	// servers are Servers.
	Endpoint string   `json:"endpoint"`
	Servers  []string `json:"servers"`
	// Client is the client's name and version as it gave them.
	Client principal.Client `json:"client"`
	// Requested is the protocol version the client asked for, Protocol
	// the one it got, Capped the agents.max_version that lowered it.
	Requested  string    `json:"requested,omitempty"`
	Protocol   string    `json:"protocol"`
	Capped     string    `json:"capped,omitempty"`
	Started    time.Time `json:"started"`
	LastActive time.Time `json:"last_active"`
	// Instances are the ids of the instances the session uses.
	Instances []string `json:"instances,omitempty"`
	// Streams and Requests are an agent's open subscriptions/listen
	// streams and requests in flight.
	Streams  int `json:"streams,omitempty"`
	Requests int `json:"requests,omitempty"`
}

// agentClient is an agent of 2026-07-28 as last seen: a principal's
// client (name and version) on an endpoint.
type agentClient struct {
	id                string
	principal         principal.Principal
	endpoint          string
	servers           []string
	first, last       time.Time
	requests, streams int
}

// Sessions lists the clients: the initialized sessions and the agents
// seen in the last hour, oldest first.
func (r *Router) Sessions() []SessionInfo {
	r.init()
	r.mu.Lock()
	sessions := make([]*Session, 0, len(r.sessions))
	for s := range r.sessions {
		sessions = append(sessions, s)
	}
	r.mu.Unlock()
	out := []SessionInfo{}
	for _, s := range sessions {
		ep := s.endpoint()
		s.mu.Lock()
		if !s.initialized {
			s.mu.Unlock()
			continue // a connection of modern requests only, or not yet begun
		}
		info := SessionInfo{ID: s.principal.SessionID, Kind: "session", Sub: s.principal.Sub, Issuer: s.principal.Issuer,
			UID: s.principal.UID, Transport: s.principal.Transport, Endpoint: endpointLabel(ep), Servers: slices.Clone(ep.order),
			Client: s.principal.Client, Requested: s.requested, Protocol: s.version, Capped: s.capped,
			Started: s.started, LastActive: time.Unix(0, s.active.Load())}
		for _, u := range s.upstreams {
			info.Instances = append(info.Instances, u.id)
		}
		s.mu.Unlock()
		slices.Sort(info.Instances)
		out = append(out, info)
	}
	r.agentMu.Lock()
	r.pruneAgentClients(time.Now())
	for _, c := range r.agents.clients {
		out = append(out, SessionInfo{ID: c.id, Kind: "agent", Sub: c.principal.Sub, Issuer: c.principal.Issuer,
			UID: c.principal.UID, Transport: c.principal.Transport, Endpoint: c.endpoint, Servers: slices.Clone(c.servers),
			Client: c.principal.Client, Requested: modernVersion, Protocol: modernVersion,
			Started: c.first, LastActive: c.last, Streams: c.streams, Requests: c.requests})
	}
	r.agentMu.Unlock()
	slices.SortFunc(out, func(a, b SessionInfo) int {
		if c := a.Started.Compare(b.Started); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// endpointLabel names an endpoint in the list: its server, or "all".
func endpointLabel(ep endpoint) string {
	if ep.aggregated {
		return "all"
	}
	return ep.order[0]
}

// agentSeen records a request of the modern agent of request session s
// (a subscription stream if stream); done, when it is answered or the
// stream ends.
func (r *Router) agentSeen(s *Session, stream bool) (done func()) {
	p := s.snapshotPrincipal()
	ep := s.endpoint()
	key := s.binding() + "\x00" + s.endpointName() + "\x00" + p.Client.Name + "\x00" + p.Client.Version
	now := time.Now()
	r.agentMu.Lock()
	defer r.agentMu.Unlock()
	if r.agents.clients == nil {
		r.agents.clients = map[string]*agentClient{}
	}
	c := r.agents.clients[key]
	if c == nil {
		sum := sha256.Sum256([]byte(key))
		c = &agentClient{id: "agent-" + hex.EncodeToString(sum[:8]), principal: p, first: now}
		r.agents.clients[key] = c
	}
	c.endpoint, c.servers, c.last = endpointLabel(ep), slices.Clone(ep.order), now
	if stream {
		c.streams++
	} else {
		c.requests++
	}
	r.pruneAgentClients(now)
	return func() {
		r.agentMu.Lock()
		defer r.agentMu.Unlock()
		if stream {
			c.streams--
		} else {
			c.requests--
		}
		c.last = time.Now()
	}
}

// pruneAgentClients drops the agents not seen for agentSeenFor and, of a
// principal with more than limits.sessions_per_principal, the ones seen
// longest ago; an agent with a request or stream open stays. Under
// r.agentMu.
func (r *Router) pruneAgentClients(now time.Time) {
	max := r.settings().MaxSessionsPerPrincipal
	if max <= 0 {
		max = defaultSessionsPerPrincipal
	}
	byPrincipal := map[string][]string{}
	for k, c := range r.agents.clients {
		busy := c.requests > 0 || c.streams > 0
		if !busy && now.Sub(c.last) > agentSeenFor {
			delete(r.agents.clients, k)
			continue
		}
		pk := principalKey(c.principal)
		byPrincipal[pk] = append(byPrincipal[pk], k)
	}
	for _, keys := range byPrincipal {
		if len(keys) <= max {
			continue
		}
		slices.SortFunc(keys, func(a, b string) int {
			return r.agents.clients[a].last.Compare(r.agents.clients[b].last)
		})
		n := len(keys)
		for _, k := range keys {
			if n <= max {
				break
			}
			if c := r.agents.clients[k]; c.requests == 0 && c.streams == 0 {
				delete(r.agents.clients, k)
				n--
			}
		}
	}
}
