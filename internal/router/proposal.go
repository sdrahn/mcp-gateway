package router

import (
	"encoding/json"
	"errors"

	"github.com/sdrahn/mcp-gateway/internal/proposal"
)

// takeProposal takes the client's proposal out of a request's _meta,
// whatever the method, so that no server receives it, and keeps it for a
// tools/call (t.proposal). A malformed or oversized one is dropped, not
// the call: the drop is audited (mcp-proposal-dropped).
func (s *Session) takeProposal(method string, t *callTarget, params map[string]json.RawMessage) {
	meta, ok := params["_meta"]
	if !ok {
		return
	}
	rest, p, err := proposal.Take(meta)
	params["_meta"] = rest
	if method != "tools/call" {
		return
	}
	if errors.Is(err, proposal.ErrInvalid) {
		pr := s.snapshotPrincipal()
		s.r.Audit.Note("mcp-proposal-dropped", map[string]string{"session": pr.SessionID, "sub": pr.Sub,
			"server": t.server, "name": t.resource.Name, "reason": err.Error()})
		s.log.Info("proposal dropped", "server", t.server, "name", t.resource.Name, "err", err)
		return
	}
	t.proposal = p
}

// proposalRecord is p for an audit record: nil (not a typed nil) when
// there is none.
func proposalRecord(p *proposal.Proposal) any {
	if p == nil {
		return nil
	}
	return p
}
