package router

import (
	"sort"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// Namespacing on the aggregated endpoint (docs/architecture.md, 5.3).
const (
	// nameSep joins server and tool/prompt names: "fs__read_file". Backend
	// names cannot contain it (config: [a-z][a-z0-9-]*).
	nameSep = "__"
	// uriPrefix starts namespaced resource URIs: "mcp+fs:file:///x".
	uriPrefix = "mcp+"
)

// endpoint is what a client connection talks to: one backend, or all of
// them aggregated.
type endpoint struct {
	aggregated bool
	backends   map[string]*config.Backend
	order      []string
}

func singleEndpoint(b *config.Backend) endpoint {
	return endpoint{backends: map[string]*config.Backend{b.Name: b}, order: []string{b.Name}}
}

func aggregatedEndpoint(all map[string]*config.Backend) endpoint {
	e := endpoint{aggregated: true, backends: all}
	for name := range all {
		e.order = append(e.order, name)
	}
	sort.Strings(e.order)
	return e
}

// exposeName maps a backend tool/prompt name to the name the client sees.
func (e endpoint) exposeName(server, name string) string {
	if !e.aggregated {
		return name
	}
	return server + nameSep + name
}

// resolveName maps a client-visible tool/prompt name to backend and name.
func (e endpoint) resolveName(n string) (server, name string, ok bool) {
	if !e.aggregated {
		return e.order[0], n, n != ""
	}
	server, name, found := strings.Cut(n, nameSep)
	if !found || name == "" || e.backends[server] == nil {
		return "", "", false
	}
	return server, name, true
}

// exposeURI maps a backend resource URI (or URI template) to the one the
// client sees.
func (e endpoint) exposeURI(server, uri string) string {
	if !e.aggregated {
		return uri
	}
	return uriPrefix + server + ":" + uri
}

// resolveURI maps a client-visible resource URI to backend and URI.
func (e endpoint) resolveURI(u string) (server, uri string, ok bool) {
	if !e.aggregated {
		return e.order[0], u, u != ""
	}
	rest, found := strings.CutPrefix(u, uriPrefix)
	if !found {
		return "", "", false
	}
	server, uri, found = strings.Cut(rest, ":")
	if !found || uri == "" || e.backends[server] == nil {
		return "", "", false
	}
	return server, uri, true
}
