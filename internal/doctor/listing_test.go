package doctor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// errOPAConflict is OPA's answer to issue #298's listing.
var errOPAConflict = errors.New(`opa: 500 Internal Server Error: {
  "code": "internal_error",
  "message": "error(s) occurred while evaluating query",
  "errors": [{"code": "eval_conflict_error", "message": "complete rules must not produce multiple outputs",
    "location": {"file": "usr/share/mcp-gateway/policy/mcp/authz.rego", "row": 235, "col": 1}}]
}`)

func TestListings(t *testing.T) {
	rs := []pep.Resource{
		{Server: "fs", Kind: "tool", Name: "read_file"},
		{Server: "tukit", Kind: "tool", Name: "reboot", Privileged: true},
		{Server: "tukit", Kind: "tool", Name: "apply", Privileged: true},
	}
	ps := []ListingPrincipal{
		{Label: "drahn (groups wheel)", Principal: principal.Principal{Sub: "drahn", Groups: []string{"wheel"}}},
		{Label: "alice", Principal: principal.Principal{Sub: "alice"}},
		{Label: "a member of ops", Principal: principal.Principal{Sub: "mcp-doctor", Groups: []string{"ops"}}},
	}
	// drahn's roles fail every listing with tukit in it.
	visible := func(_ context.Context, p principal.Principal, rs []pep.Resource) ([]pep.Resource, error) {
		for _, r := range rs {
			if p.Sub == "drahn" && r.Server == "tukit" {
				return nil, errOPAConflict
			}
		}
		return rs, nil
	}
	r := Listings(context.Background(), ps, rs, visible)
	if r.Status != Fail || r.Summary != "the policy fails the listing of 1 of 3 principals: the gateway shows them no tools at all" {
		t.Fatalf("%+v", r)
	}
	if want := "drahn (groups wheel): at server tukit: eval_conflict_error: complete rules must not produce multiple outputs (authz.rego:235)"; r.Details[0] != want {
		t.Errorf("details %q, want %q", r.Details[0], want)
	}
	rs2 := []Result{r}
	Identify(rs2)
	if rs2[0].ID != "policy-listing" {
		t.Errorf("id %q", rs2[0].ID)
	}

	ok := func(_ context.Context, _ principal.Principal, rs []pep.Resource) ([]pep.Resource, error) {
		return rs, nil
	}
	if r := Listings(context.Background(), ps, rs, ok); r.Status != OK || r.Summary != "the policy decides the listings of 3 principals (3 tools of 2 servers)" {
		t.Errorf("ok: %+v", r)
	}
	// Failing everywhere: every server.
	all := func(context.Context, principal.Principal, []pep.Resource) ([]pep.Resource, error) {
		return nil, errors.New("opa: connection refused")
	}
	if r := Listings(context.Background(), ps[:1], rs, all); r.Status != Fail || !strings.Contains(r.Details[0], "at every server: opa: connection refused") {
		t.Errorf("all: %+v", r)
	}
	if r := Listings(context.Background(), nil, rs, ok); r.Status != Skip {
		t.Errorf("no principals: %+v", r)
	}
}

func TestOPAError(t *testing.T) {
	if got := OPAError(errOPAConflict); got != "eval_conflict_error: complete rules must not produce multiple outputs (authz.rego:235)" {
		t.Errorf("%q", got)
	}
	if got := OPAError(errors.New("opa: timeout")); got != "opa: timeout" {
		t.Errorf("%q", got)
	}
}
