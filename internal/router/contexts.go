package router

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Contexts (docs/architecture.md, decision D22): a server with contexts
// (and isolation: session) offers modern agents, which have no session,
// the tools gateway_new_context and gateway_end_context, and an argument
// gateway_context on each of its tools. A call with a context runs in
// the context's own instance; a call without, in the principal's. A
// context belongs to the principal and server it was opened for and ends
// with gateway_end_context or after the idle timeout
// (supervisor.idle_timeout) without a call; its instance ends with it.
// Contexts live in the gateway's memory: a restart ends them.

const (
	newContextTool = "gateway_new_context"
	endContextTool = "gateway_end_context"
	// contextArg is the argument naming the context of a call.
	contextArg = "gateway_context"
	// contextGrace is how long a context's instance outlasts the
	// context's idle timeout.
	contextGrace = time.Minute
	// defaultContextsPerPrincipal is Settings.MaxContextsPerPrincipal's
	// default.
	defaultContextsPerPrincipal = 8
)

// agentContext is an open context.
type agentContext struct {
	owner  string // principalKey
	server string
	last   time.Time
}

// contextStore holds the open contexts.
type contextStore struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]*agentContext
}

func (c *contextStore) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// expire drops the contexts idle for longer than idle; c.mu must be held.
func (c *contextStore) expire(idle time.Duration) {
	now := c.clock()
	for id, ac := range c.m {
		if idle > 0 && now.Sub(ac.last) > idle {
			delete(c.m, id)
		}
	}
}

// open opens a context of server for p; at max contexts of p it fails.
func (c *contextStore) open(p principal.Principal, server string, max int, idle time.Duration) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire(idle)
	owner := principalKey(p)
	n := 0
	for _, ac := range c.m {
		if ac.owner == owner {
			n++
		}
	}
	if max > 0 && n >= max {
		return "", &LimitError{Limit: "contexts_per_principal", Max: max}
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := "ctx_" + base64.RawURLEncoding.EncodeToString(b)
	if c.m == nil {
		c.m = map[string]*agentContext{}
	}
	c.m[id] = &agentContext{owner: owner, server: server, last: c.clock()}
	return id, nil
}

// use marks a call of server for p in context id, which must be p's,
// of server and open.
func (c *contextStore) use(p principal.Principal, server, id string, idle time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire(idle)
	ac := c.m[id]
	if ac == nil || ac.owner != principalKey(p) || ac.server != server {
		return false
	}
	ac.last = c.clock()
	return true
}

// end ends p's context id of server; it reports whether it was open.
func (c *contextStore) end(p principal.Principal, server, id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	ac := c.m[id]
	if ac == nil || ac.owner != principalKey(p) || ac.server != server {
		return false
	}
	delete(c.m, id)
	return true
}

// list returns p's open contexts of server, sorted.
func (c *contextStore) list(p principal.Principal, server string, idle time.Duration) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire(idle)
	owner := principalKey(p)
	var ids []string
	for _, id := range slices.Sorted(maps.Keys(c.m)) {
		if ac := c.m[id]; ac.owner == owner && ac.server == server {
			ids = append(ids, id)
		}
	}
	return ids
}

// offersContexts reports whether the session offers contexts of b: to a
// modern agent (no session), for a server with contexts.
func (s *Session) offersContexts(b *config.Backend) bool {
	return b != nil && b.Contexts && b.Isolation == config.IsolationSession && s.snapshotPrincipal().SessionID == ""
}

// contextItems are the context tools of server, as tools/list shows them.
func contextItems(server string, idle time.Duration) []listItem {
	newRaw := map[string]json.RawMessage{}
	newRaw["name"], _ = json.Marshal(newContextTool)
	newRaw["title"], _ = json.Marshal("New " + server + " context")
	newRaw["description"], _ = json.Marshal(fmt.Sprintf("Open a context of %s of your own: a separate instance of the server, "+
		"with its own state. Pass the id it returns as %s to %s's tools to use it; calls without it share your one "+
		"instance. A context ends with %s, or after %s without a call.", server, contextArg, server, endContextTool, idle))
	newRaw["inputSchema"] = json.RawMessage(`{"type":"object","properties":{}}`)
	newRaw["outputSchema"] = json.RawMessage(`{"type":"object","properties":{"context":{"type":"string"}},"required":["context"]}`)
	newRaw["annotations"] = json.RawMessage(`{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}`)

	endRaw := map[string]json.RawMessage{}
	endRaw["name"], _ = json.Marshal(endContextTool)
	endRaw["title"], _ = json.Marshal("End a " + server + " context")
	endRaw["description"], _ = json.Marshal(fmt.Sprintf("End a context of %s opened with %s: its instance stops and its state is lost.",
		server, newContextTool))
	endRaw["inputSchema"] = json.RawMessage(`{"type":"object","properties":{"` + contextArg + `":{"type":"string","description":"The context's id."}},"required":["` + contextArg + `"]}`)
	endRaw["annotations"] = json.RawMessage(`{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":true,"openWorldHint":false}`)
	return []listItem{
		{server: server, name: newContextTool, raw: newRaw, context: true},
		{server: server, name: endContextTool, raw: endRaw, context: true},
	}
}

// withContextArg adds the optional argument gateway_context to a tool's
// input schema; a schema that has it already, or is no object schema, is
// left as it is (false).
func withContextArg(raw map[string]json.RawMessage, server string) bool {
	var schema map[string]json.RawMessage
	if json.Unmarshal(raw["inputSchema"], &schema) != nil || schema == nil {
		return false
	}
	var props map[string]json.RawMessage
	if p, ok := schema["properties"]; ok {
		if json.Unmarshal(p, &props) != nil || props == nil {
			return false
		}
	} else {
		props = map[string]json.RawMessage{}
	}
	if _, taken := props[contextArg]; taken {
		return false
	}
	props[contextArg], _ = json.Marshal(map[string]string{
		"type": "string",
		"description": fmt.Sprintf("Optional: the id of a context from %s, to run the call in that context's own instance of %s.",
			newContextTool, server),
	})
	schema["properties"], _ = json.Marshal(props)
	raw["inputSchema"], _ = json.Marshal(schema)
	return true
}

// takeContext removes the argument gateway_context from the arguments of
// a call of a server whose contexts the session offers, and makes the
// session's calls run in that context, which must be the principal's and
// open. It is an invalid-params error otherwise.
func (s *Session) takeContext(t *callTarget, params map[string]json.RawMessage) *jsonrpc.Error {
	raw, ok := t.args[contextArg]
	if !ok {
		return nil
	}
	id, isString := raw.(string)
	if !isString {
		return rpcError(jsonrpc.CodeInvalidParams, "invalid params: "+contextArg+" must be a string")
	}
	p := s.snapshotPrincipal()
	if !s.r.contexts.use(p, t.server, id, s.r.settings().IdleTimeout) {
		return rpcError(jsonrpc.CodeInvalidParams, fmt.Sprintf("invalid params: no open context %q of %s; "+
			"open one with %s (contexts end after %s without a call, and when the gateway restarts)",
			id, t.server, s.endpoint().exposeName(t.server, newContextTool), s.r.settings().IdleTimeout))
	}
	delete(t.args, contextArg)
	var args map[string]json.RawMessage
	if json.Unmarshal(params["arguments"], &args) == nil {
		delete(args, contextArg)
		params["arguments"], _ = json.Marshal(args)
	}
	s.mu.Lock()
	s.principal.Context = id
	u := s.upstreams[t.server]
	s.mu.Unlock()
	if u != nil {
		// The principal's own instance, which listing the server's tools
		// may have started: the call goes to the context's.
		s.leave(t.server, u)
	}
	return nil
}

// contextTool answers a call of gateway_new_context or
// gateway_end_context, which policy allowed.
func (s *Session) contextTool(ctx context.Context, t *callTarget) (any, *jsonrpc.Error) {
	p := s.snapshotPrincipal()
	set := s.r.settings()
	switch t.resource.Name {
	case newContextTool:
		id, err := s.r.contexts.open(p, t.server, set.MaxContextsPerPrincipal, set.IdleTimeout)
		if err != nil {
			open := s.r.contexts.list(p, t.server, set.IdleTimeout)
			return nil, rpcError(jsonrpc.CodeInternalError, fmt.Sprintf("mcp-gateway: %v (limits.contexts_per_principal); end one with %s (open contexts of %s: %s)",
				err, s.endpoint().exposeName(t.server, endContextTool), t.server, strings.Join(open, ", ")))
		}
		s.r.Audit.Note("mcp-context", map[string]string{"principal": p.Sub, "transport": string(p.Transport),
			"server": t.server, "context": id, "op": "open"})
		s.log.Info("context opened", "server", t.server, "context", id)
		text := fmt.Sprintf("Opened context %s of %s. Pass %q: %q to %s's tools to run them in it.", id, t.server, contextArg, id, t.server)
		return map[string]any{
			"content":           []map[string]any{{"type": "text", "text": text}},
			"structuredContent": map[string]any{"context": id},
		}, nil
	case endContextTool:
		id, _ := t.args[contextArg].(string)
		if !s.r.contexts.end(p, t.server, id) {
			return nil, rpcError(jsonrpc.CodeInvalidParams, fmt.Sprintf("invalid params: no open context %q of %s", id, t.server))
		}
		n := s.r.pool.stopFor(t.server, func(ip principal.Principal) bool { return ip.Context == id })
		s.r.Audit.Note("mcp-context", map[string]string{"principal": p.Sub, "transport": string(p.Transport),
			"server": t.server, "context": id, "op": "end"})
		s.log.Info("context ended", "server", t.server, "context", id, "instances", n)
		return textResult(fmt.Sprintf("Ended context %s of %s.", id, t.server)), nil
	}
	return nil, rpcError(jsonrpc.CodeInvalidParams, "unknown tool or prompt")
}
