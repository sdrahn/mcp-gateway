package router

import (
	"time"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/pseudo"
)

// What a session held for a legacy agent belongs to the principal for a
// modern one (docs/architecture.md, section 5.11.3): the pseudonym vault,
// per principal and endpoint and dropped when idle, and the limits, on
// requests in flight and subscription streams instead of sessions.

const (
	defaultRequestsPerPrincipal = 64
	defaultStreamsPerPrincipal  = 16
	defaultVaultIdle            = time.Hour
)

// agentRegistry is the router's state of modern agents.
type agentRegistry struct {
	vaults map[string]*agentVault
	// requests and streams count the principals' requests in flight and
	// open subscription streams.
	requests, streams map[string]int
}

type agentVault struct {
	vault *pseudo.Vault
	used  time.Time
}

// agentVault returns the pseudonym vault of s's principal and endpoint,
// and drops the vaults idle longer than pseudonymize.vault_idle.
func (r *Router) agentVault(s *Session) *pseudo.Vault {
	key := s.binding() + "\x00" + s.endpointName()
	idle := r.settings().VaultIdle
	now := time.Now()
	r.agentMu.Lock()
	defer r.agentMu.Unlock()
	if r.agents.vaults == nil {
		r.agents.vaults = map[string]*agentVault{}
	}
	for k, v := range r.agents.vaults {
		if now.Sub(v.used) > idle {
			delete(r.agents.vaults, k)
		}
	}
	v := r.agents.vaults[key]
	if v == nil {
		v = &agentVault{vault: pseudo.NewVault(0)}
		r.agents.vaults[key] = v
	}
	v.used = now
	return v.vault
}

// admitAgentRequest counts a modern request of p (a subscription stream
// if stream) against the principal's limit; release uncounts it. At the
// limit the request is refused.
func (r *Router) admitAgentRequest(p principal.Principal, stream bool) (release func(), err *LimitError) {
	key := principalKey(p)
	limit, max := "requests_per_principal", r.settings().MaxRequestsPerPrincipal
	if stream {
		limit, max = "streams_per_principal", r.settings().MaxStreamsPerPrincipal
	}
	r.agentMu.Lock()
	counts := &r.agents.requests
	if stream {
		counts = &r.agents.streams
	}
	if *counts == nil {
		*counts = map[string]int{}
	}
	if (*counts)[key] >= max {
		r.agentMu.Unlock()
		e := &LimitError{Limit: limit, Max: max}
		r.refused(p, e)
		return nil, e
	}
	(*counts)[key]++
	r.agentMu.Unlock()
	return func() {
		r.agentMu.Lock()
		defer r.agentMu.Unlock()
		if (*counts)[key]--; (*counts)[key] <= 0 {
			delete(*counts, key)
		}
	}, nil
}

// limitError is the agent's error for a request refused at a limit.
func limitError(e *LimitError) *jsonrpc.Error {
	return rpcError(jsonrpc.CodeInternalError, "mcp-gateway: "+e.Error())
}
