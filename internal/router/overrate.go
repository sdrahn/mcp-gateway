package router

import (
	"fmt"

	"github.com/sdrahn/mcp-gateway/internal/pep"
)

// overRate applies a call's rates where policy allowed it without an
// approval: rate_limit, the hard cap, denies over its rates; over one of
// approval_over_rate the allow becomes an ask, out of band and for this
// call only (a grant for a session or a time would lift the rate), whose
// prompt names the rate reached. Within both, the call is counted for both
// and goes on. A call approved this way is not counted: a person decided
// on it (the decision after the approval does not come here).
//
// later is a later round of a modern agent's call already waiting for
// such an approval: only approval_over_rate is checked again (the hard cap
// counted the call in its first round).
func (s *Session) overRate(t *callTarget, dec pep.Decision, later bool) pep.Decision {
	if dec.Effect != pep.Allow || dec.Obligations == nil || len(dec.Obligations.ApprovalOverRate) == 0 {
		return dec
	}
	ob, err := dec.Obligations.Compile()
	if err != nil || len(ob.OverRates) == 0 {
		return dec // denied as invalid obligations by the call
	}
	p := s.snapshotPrincipal()
	key := rateKey(p, t)
	if !later {
		t.ratesCounted = true
		if !s.r.limiter.Allow(key, ob.Rates) {
			return pep.Decision{Effect: pep.Deny, Reason: "rate limit exceeded"}
		}
	}
	rate, over := s.r.limiter.Exceeded("approval_over_rate\x00"+key, ob.OverRates)
	if !over {
		return dec
	}
	t.overRate = rate.String()
	return pep.Decision{Effect: pep.Ask, Obligations: dec.Obligations, Ask: &pep.AskSpec{
		Channel:  pep.ChannelOOB,
		Prompt:   fmt.Sprintf("Rate %s reached for %s on %s %s: allow this call?", t.overRate, p.Sub, t.resource.Server, t.resource.Name),
		Scopes:   []string{"once"},
		OverRate: t.overRate,
	}}
}
