package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// ListingProbe is the tool name a listing is decided for on a server whose
// tools are not known (not started, or started per user): it exercises
// the permissions with wildcards, which name no tool.
const ListingProbe = "mcp-doctor-probe"

// ListingPrincipal is one principal to decide a listing for, with a label
// for the result ("drahn (groups wheel, users)", "a member of ops").
type ListingPrincipal struct {
	Label     string
	Principal principal.Principal
}

// Visible decides a listing (pep.OPA.Visible).
type Visible func(ctx context.Context, p principal.Principal, rs []pep.Resource) ([]pep.Resource, error)

// Listings decides a tools/list for each principal over resources, as the
// gateway does for a client, and fails for every principal whose listing
// the policy cannot decide: the gateway then hides every tool of every
// server from them ("filtering failed; hiding everything"). For each, it
// decides the listing again server by server to name the servers it fails
// for, and gives OPA's error. The policy check decides one call for an
// unknown principal only, which does not reach the rules a principal's
// roles do (issue #298: two channels for one tool).
func Listings(ctx context.Context, ps []ListingPrincipal, rs []pep.Resource, visible Visible) Result {
	r := Result{Check: "policy listing"}
	if len(ps) == 0 || len(rs) == 0 {
		r.Status, r.Summary = Skip, "no principal bound to a role, or no server"
		return r
	}
	var servers []string
	byServer := map[string][]pep.Resource{}
	for _, res := range rs {
		if byServer[res.Server] == nil {
			servers = append(servers, res.Server)
		}
		byServer[res.Server] = append(byServer[res.Server], res)
	}
	slices.Sort(servers)
	var failed []string
	for _, p := range ps {
		if _, err := visible(ctx, p.Principal, rs); err == nil {
			continue
		} else if ctx.Err() != nil {
			r.Status, r.Summary = Fail, "OPA does not decide in time: "+err.Error()
			return r
		} else {
			var at []string
			for _, s := range servers {
				if _, err := visible(ctx, p.Principal, byServer[s]); err != nil {
					at = append(at, s)
				}
			}
			where := "every server"
			if len(at) > 0 && len(at) < len(servers) {
				where = "server " + strings.Join(at, ", ")
			}
			failed = append(failed, fmt.Sprintf("%s: at %s: %s", p.Label, where, OPAError(err)))
		}
	}
	if len(failed) > 0 {
		r.Status = Fail
		r.Summary = fmt.Sprintf("the policy fails the listing of %d of %d principals: the gateway shows them no tools at all", len(failed), len(ps))
		r.Details = append(failed, "the permissions their roles combine lead the policy to an error: the decision for one of the servers' tools (gateway-admin's explain_decision) shows it; journalctl -u mcp-gateway.service shows \"filtering failed\"")
		return r
	}
	r.Status, r.Summary = OK, fmt.Sprintf("the policy decides the listings of %d principals (%d tools of %d servers)", len(ps), len(rs), len(servers))
	return r
}

// OPAError shortens an error of OPA's: the messages and locations of its
// errors ("eval_conflict_error: complete rules must not produce multiple
// outputs (authz.rego:235)"), else the error as it is.
func OPAError(err error) string {
	s := err.Error()
	i := strings.IndexByte(s, '{')
	if i < 0 {
		return s
	}
	var body struct {
		Errors []struct {
			Code     string `json:"code"`
			Message  string `json:"message"`
			Location *struct {
				File string `json:"file"`
				Row  int    `json:"row"`
			} `json:"location"`
		} `json:"errors"`
	}
	if json.Unmarshal([]byte(s[i:]), &body) != nil || len(body.Errors) == 0 {
		return s
	}
	var out []string
	for _, e := range body.Errors {
		m := e.Code + ": " + e.Message
		if e.Location != nil && e.Location.File != "" {
			file := e.Location.File
			if j := strings.LastIndexByte(file, '/'); j >= 0 {
				file = file[j+1:]
			}
			m += fmt.Sprintf(" (%s:%d)", file, e.Location.Row)
		}
		out = append(out, m)
	}
	return strings.Join(out, "; ")
}
