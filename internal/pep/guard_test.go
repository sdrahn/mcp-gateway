package pep

import (
	"context"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// allowAll is a PDP that allows and shows everything and hints at each.
type allowAll struct{}

func (allowAll) Decide(context.Context, Input) (Decision, error) {
	return Decision{Effect: Allow}, nil
}

func (allowAll) Visible(_ context.Context, _ principal.Principal, rs []Resource) ([]Resource, error) {
	return rs, nil
}

func (allowAll) Hints(_ context.Context, _ principal.Principal, rs []Resource) ([]Hint, error) {
	return []Hint{{Server: rs[0].Server, Name: rs[0].Name, Approval: "url"}}, nil
}

func TestGuard(t *testing.T) {
	ctx := context.Background()
	reason := ""
	g := Guard{PDP: allowAll{}, Blocked: func() string { return reason }}
	rs := []Resource{{Server: "fs", Kind: "tool", Name: "read_file"}}
	var p principal.Principal

	if d := Evaluate(ctx, g, Input{Action: "tools.call"}); d.Effect != Allow {
		t.Errorf("unblocked: %+v", d)
	}
	if vs, err := g.Visible(ctx, p, rs); err != nil || len(vs) != 1 {
		t.Errorf("unblocked visible: %v, %v", vs, err)
	}
	if hs, err := g.Hints(ctx, p, rs); err != nil || len(hs) != 1 {
		t.Errorf("unblocked hints: %v, %v", hs, err)
	}

	reason = "/etc/mcp-gateway/policy/rbac/data.json: configuration in JSON is no longer read since 1.7"
	if d := Evaluate(ctx, g, Input{Action: "tools.call"}); d.Effect != Deny || d.Reason != reason {
		t.Errorf("blocked: %+v", d)
	}
	if vs, err := g.Visible(ctx, p, rs); err == nil || len(vs) != 0 {
		t.Errorf("blocked visible: %v, %v", vs, err)
	}
	if hs, err := g.Hints(ctx, p, rs); err != nil || len(hs) != 0 {
		t.Errorf("blocked hints: %v, %v", hs, err)
	}
}
