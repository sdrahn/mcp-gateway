package router

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/pep"
)

// clientMethods are the requests MCP servers may send to the agent, as
// policy sees them (kind "client").
var clientMethods = []string{"sampling/createMessage", "elicitation/create", "roots/list"}

// Catalog is what the MCP servers offer, for policy reviews ("what
// changes?"): their tools, prompts and resource templates from shared
// discovery, and the requests each may send to the agent.
type Catalog struct {
	Resources []pep.Resource
	// Unchecked names the servers whose lists are unknown, with the reason:
	// discovery per user, or an error starting the discovery instance.
	Unchecked map[string]string
}

// Catalog lists what the MCP servers offer. It may start shared discovery
// instances, as the first tools/list of any session would.
func (r *Router) Catalog(ctx context.Context) Catalog {
	r.init()
	c := Catalog{Unchecked: map[string]string{}}
	names := make([]string, 0, len(r.Backends))
	for name := range r.Backends {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b := r.Backends[name]
		for _, m := range clientMethods {
			c.Resources = append(c.Resources, pep.Resource{Server: name, Kind: "client", Name: m})
		}
		if b.Discovery != config.DiscoveryShared {
			c.Unchecked[name] = "tools and prompts are listed per user (discovery: " + b.Discovery + ")"
			continue
		}
		ir, err := r.sharedInit(ctx, b)
		if err != nil {
			c.Unchecked[name] = err.Error()
			continue
		}
		for _, method := range []string{"tools/list", "prompts/list", "resources/templates/list"} {
			spec := listSpecs[method]
			if !ir.has(spec.capability) {
				continue
			}
			items, err := r.sharedList(ctx, b, method, spec)
			if err != nil {
				c.Unchecked[name] = err.Error()
				break
			}
			for _, it := range items {
				res := pep.Resource{Server: name, Kind: spec.kind, Name: it.name}
				if raw, ok := it.raw["annotations"]; ok && spec.kind == "tool" {
					_ = json.Unmarshal(raw, &res.Annotations)
				}
				c.Resources = append(c.Resources, res)
			}
		}
	}
	return c
}
