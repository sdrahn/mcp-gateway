package router

import (
	"fmt"
	"strconv"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/metrics"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Limits per principal on sessions and instances (docs/architecture.md,
// decision D14).
const (
	defaultSessionsPerPrincipal  = 64
	defaultInstancesPerPrincipal = 32
)

// principalKey identifies a principal for the limits: the key shared
// instances use.
func principalKey(p principal.Principal) string {
	return string(p.Transport) + "\x00" + p.Issuer + "\x00" + p.Sub
}

// LimitError is returned when a limit refuses a session or an instance.
type LimitError struct {
	Limit string // sessions, instances_per_principal, instances, requests_per_principal, streams_per_principal
	Max   int
}

func (e *LimitError) Error() string {
	what := map[string]string{
		"sessions":                "session limit",
		"instances_per_principal": "instance limit",
		"instances":               "gateway instance limit",
		"requests_per_principal":  "request limit",
		"streams_per_principal":   "subscription stream limit",
	}[e.Limit]
	return fmt.Sprintf("%s reached (%d)", what, e.Max)
}

// idler is implemented by client connections the gateway may end to make
// room for a new session of the same principal: HTTP sessions, which
// clients often leave without ending them. idle reports how long the
// connection has had no traffic, and whether nothing is in flight or
// attached (a local connection is never idle in this sense: the client
// holds it open).
type idler interface {
	Idle() (time.Duration, bool)
}

// admit registers s unless its principal is at the session limit. At the
// limit it first ends the principal's longest-idle evictable session (see
// idler); if there is none, it refuses.
func (r *Router) admit(s *Session) error {
	max := r.settings().MaxSessionsPerPrincipal
	if max <= 0 {
		max = defaultSessionsPerPrincipal
	}
	key := principalKey(s.principal)
	r.mu.Lock()
	if r.sessions == nil {
		r.sessions = map[*Session]struct{}{}
	}
	n := 0
	var victim *Session
	var victimIdle time.Duration
	for o := range r.sessions {
		if principalKey(o.principal) != key {
			continue
		}
		n++
		if c, ok := o.client.(idler); ok {
			if d, evictable := c.Idle(); evictable && (victim == nil || d > victimIdle) {
				victim, victimIdle = o, d
			}
		}
	}
	if n >= max && victim == nil {
		r.mu.Unlock()
		r.refused(s.principal, &LimitError{Limit: "sessions", Max: max})
		return &LimitError{Limit: "sessions", Max: max}
	}
	if n >= max {
		// Out of the count now; its Run ends when the connection closes.
		delete(r.sessions, victim)
	}
	r.sessions[s] = struct{}{}
	r.mu.Unlock()
	if n >= max {
		r.Log.Info("ended an idle session for a new one at the session limit",
			"sub", s.principal.Sub, "session", victim.principal.SessionID, "idle", victimIdle.Round(time.Second), "limit", max)
		_ = victim.client.Close()
	}
	return nil
}

// refused audits and counts a refusal at a limit.
func (r *Router) refused(p principal.Principal, e *LimitError) {
	metrics.LimitRefusals.Inc(e.Limit)
	r.Log.Warn("limit reached", "sub", p.Sub, "transport", p.Transport, "limit", e.Limit, "max", e.Max)
	r.Audit.Event("mcp-limit", false, map[string]string{
		"principal": p.Sub, "transport": string(p.Transport), "session": p.SessionID,
		"limit": e.Limit, "max": strconv.Itoa(e.Max),
	})
}
