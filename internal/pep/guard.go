package pep

import (
	"context"
	"errors"

	"github.com/sdrahn/mcp-gateway/internal/metrics"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// A Guard is a PDP that fails closed while Blocked gives a reason: every
// decision is a deny with that reason, and no listing shows anything. The
// gateway blocks while configuration in JSON is left over, which is no
// longer read (docs/architecture.md, roadmap step 38): without it the
// policy might allow what that configuration denied.
type Guard struct {
	PDP
	Blocked func() string // "" while the PDP decides
}

// Decide implements Decider.
func (g Guard) Decide(ctx context.Context, in Input) (Decision, error) {
	if reason := g.Blocked(); reason != "" {
		metrics.PolicyFailures.Inc("blocked")
		return Decision{Effect: Deny, Reason: reason}, nil
	}
	return g.PDP.Decide(ctx, in)
}

// Visible implements Filterer: an error while blocked, which hides
// everything.
func (g Guard) Visible(ctx context.Context, p principal.Principal, rs []Resource) ([]Resource, error) {
	if reason := g.Blocked(); reason != "" {
		return nil, errors.New(reason)
	}
	return g.PDP.Visible(ctx, p, rs)
}

// Hints implements Hinter: none while blocked, or if the PDP gives none.
func (g Guard) Hints(ctx context.Context, p principal.Principal, rs []Resource) ([]Hint, error) {
	h, ok := g.PDP.(Hinter)
	if !ok || g.Blocked() != "" {
		return nil, nil
	}
	return h.Hints(ctx, p, rs)
}
