package pep

import (
	"context"
	"errors"
	"fmt"

	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// PolicyError is OPA's answer with an error status: the query reached
// OPA and it did not decide it (eval_conflict_error, a builtin's error),
// unlike an OPA out of reach or too slow.
type PolicyError struct {
	Status string
	Body   []byte
}

func (e *PolicyError) Error() string { return fmt.Sprintf("opa: %s: %s", e.Status, e.Body) }

// Undecided is a server whose resources a listing could not decide, with
// the resources (all the server's, or those of them that fail alone) and
// the policy's error.
type Undecided struct {
	Server    string
	Resources []Resource
	Err       error
}

// VisibleContained decides a listing as Visible does, and when the
// policy fails it (a PolicyError), decides it again server by server, and
// for each server that fails, resource by resource: what the policy
// cannot decide is hidden alone, and no longer every resource of every
// server. undecided lists what is hidden so. When every server fails,
// the resources are not decided one by one (the policy fails for the
// principal, not for a resource). Errors other than a PolicyError (OPA
// out of reach, the context done) are returned as they are, nothing
// decided.
func VisibleContained(ctx context.Context, f Filterer, p principal.Principal, rs []Resource) (vs []Resource, undecided []Undecided, err error) {
	vs, err = f.Visible(ctx, p, rs)
	var pe *PolicyError
	if err == nil || !errors.As(err, &pe) {
		return vs, nil, err
	}
	var servers []string
	byServer := map[string][]Resource{}
	for _, r := range rs {
		if byServer[r.Server] == nil {
			servers = append(servers, r.Server)
		}
		byServer[r.Server] = append(byServer[r.Server], r)
	}
	vs = nil
	type failure struct {
		server string
		err    error
	}
	var failed []failure
	for _, s := range servers {
		v, err := f.Visible(ctx, p, byServer[s])
		if err != nil {
			if !errors.As(err, &pe) {
				return nil, nil, err
			}
			failed = append(failed, failure{s, err})
			continue
		}
		vs = append(vs, v...)
	}
	if len(failed) == len(servers) && len(servers) > 1 {
		for _, fl := range failed {
			undecided = append(undecided, Undecided{fl.server, byServer[fl.server], fl.err})
		}
		return vs, undecided, nil
	}
	for _, fl := range failed {
		u := Undecided{Server: fl.server, Err: fl.err}
		for _, r := range byServer[fl.server] {
			v, err := f.Visible(ctx, p, []Resource{r})
			if err != nil {
				if !errors.As(err, &pe) {
					return nil, nil, err
				}
				u.Resources = append(u.Resources, r)
				u.Err = err
				continue
			}
			vs = append(vs, v...)
		}
		if len(u.Resources) > 0 {
			undecided = append(undecided, u)
		}
	}
	return vs, undecided, nil
}

// FilterFunc is a function deciding a listing, as a Filterer.
type FilterFunc func(ctx context.Context, p principal.Principal, rs []Resource) ([]Resource, error)

// Visible implements Filterer.
func (f FilterFunc) Visible(ctx context.Context, p principal.Principal, rs []Resource) ([]Resource, error) {
	return f(ctx, p, rs)
}
