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

// recorder is a PDP that keeps what it was asked.
type recorder struct {
	in Input
	rs []Resource
}

func (r *recorder) Decide(_ context.Context, in Input) (Decision, error) {
	r.in = in
	return Decision{Effect: Allow}, nil
}

func (r *recorder) Visible(_ context.Context, _ principal.Principal, rs []Resource) ([]Resource, error) {
	r.rs = rs
	return rs, nil
}

// The Guard names a discovered server's Service in every resource it
// passes on, and leaves the caller's resources as they were.
func TestGuardDiscovered(t *testing.T) {
	ctx := context.Background()
	rec := &recorder{}
	found := &Discovered{Namespace: "team-a", Service: "tickets"}
	g := Guard{PDP: rec, Blocked: func() string { return "" }, Discovered: func(server string) *Discovered {
		if server == "team-a-tickets" {
			return found
		}
		return nil
	}}
	Evaluate(ctx, g, Input{Action: "tools.call", Resource: Resource{Server: "team-a-tickets", Kind: "tool", Name: "open"}})
	if rec.in.Resource.Discovered != found {
		t.Errorf("decide: %+v", rec.in.Resource)
	}
	Evaluate(ctx, g, Input{Action: "tools.call", Resource: Resource{Server: "git", Kind: "tool", Name: "log"}})
	if rec.in.Resource.Discovered != nil {
		t.Errorf("a server file's: %+v", rec.in.Resource)
	}
	rs := []Resource{{Server: "git", Kind: "tool", Name: "log"}, {Server: "team-a-tickets", Kind: "tool", Name: "open"}}
	if _, err := g.Visible(ctx, principal.Principal{}, rs); err != nil {
		t.Fatal(err)
	}
	if rec.rs[0].Discovered != nil || rec.rs[1].Discovered != found {
		t.Errorf("visible: %+v", rec.rs)
	}
	if rs[1].Discovered != nil {
		t.Error("the caller's resources changed")
	}
}
