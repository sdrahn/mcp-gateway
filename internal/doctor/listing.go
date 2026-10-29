package doctor

import (
	"context"
	"encoding/json"
	"fmt"
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
// gateway does for a client (pep.VisibleContained), and fails for every
// principal some of whose tools the policy cannot decide: the gateway
// hides those from them ("filtering failed" in its journal), naming the
// servers and tools and OPA's error. The policy check decides one call
// for an unknown principal only, which does not reach the rules a
// principal's roles do (issue #298: two channels for one tool).
func Listings(ctx context.Context, ps []ListingPrincipal, rs []pep.Resource, visible Visible) Result {
	r := Result{Check: "policy listing"}
	if len(ps) == 0 || len(rs) == 0 {
		r.Status, r.Summary = Skip, "no principal bound to a role, or no server"
		return r
	}
	servers := map[string]bool{}
	for _, res := range rs {
		servers[res.Server] = true
	}
	var failed []string
	for _, p := range ps {
		_, undecided, err := pep.VisibleContained(ctx, pep.FilterFunc(visible), p.Principal, rs)
		if err != nil {
			if ctx.Err() != nil {
				r.Status, r.Summary = Fail, "OPA does not decide in time: "+err.Error()
				return r
			}
			failed = append(failed, fmt.Sprintf("%s: every tool: %s", p.Label, OPAError(err)))
			continue
		}
		if len(undecided) == 0 {
			continue
		}
		var at []string
		for _, u := range undecided {
			names := make([]string, len(u.Resources))
			for i, res := range u.Resources {
				names[i] = res.Name
			}
			if len(u.Resources) == len(byServer(rs, u.Server)) {
				at = append(at, "server "+u.Server)
			} else {
				at = append(at, u.Server+" "+strings.Join(names, ", "))
			}
		}
		failed = append(failed, fmt.Sprintf("%s: %s: %s", p.Label, strings.Join(at, "; "), OPAError(undecided[0].Err)))
	}
	if len(failed) > 0 {
		r.Status = Fail
		r.Summary = fmt.Sprintf("the policy cannot decide tools for %d of %d principals: the gateway hides those tools from them", len(failed), len(ps))
		r.Details = append(failed, "the permissions their roles combine lead the policy to an error: the decision for one of these tools (gateway-admin's explain_decision) shows it; journalctl -u mcp-gateway.service shows \"filtering failed\"")
		return r
	}
	r.Status, r.Summary = OK, fmt.Sprintf("the policy decides the listings of %d principals (%d tools of %d servers)", len(ps), len(rs), len(servers))
	return r
}

func byServer(rs []pep.Resource, server string) []pep.Resource {
	var out []pep.Resource
	for _, r := range rs {
		if r.Server == server {
			out = append(out, r)
		}
	}
	return out
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
		m := e.Code + ": " + oneLine(e.Message)
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

// oneLine folds a message of several lines onto one, its later lines
// separated by "; ": OPA 1.22 names a conflict's values on lines of
// their own ("rule … produced conflicting values:\n  1 at f:5\n  2 at
// f:7").
func oneLine(msg string) string {
	var parts []string
	for _, l := range strings.Split(msg, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			parts = append(parts, l)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0] + " " + strings.Join(parts[1:], "; "))
}
