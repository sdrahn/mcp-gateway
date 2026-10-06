package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/mcpheader"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

// Agents of MCP 2026-07-28 and later ("modern", docs/architecture.md,
// section 5.11.1) send no initialize: each request carries its protocol
// version, the client's capabilities and log level in its _meta, and is
// served on its own, beside the legacy sessions on the same endpoints. A
// request gets a session of its own for the time it is served (the
// request session), with no session id: instances are per principal
// (for isolation: session too), and it does not count as a session.

// agentVersions are the protocol versions the gateway speaks to agents,
// newest first: the modern one per request, the legacy ones at initialize.
var agentVersions = []string{modernVersion, "2025-11-25", "2025-06-18", "2025-03-26"}

// codeResourceNotFound is the legacy code for an unknown resource; modern
// requests get -32602 instead.
const codeResourceNotFound = -32002

// logLevels orders the MCP log levels.
var logLevels = []string{"debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"}

// agentMeta is what a modern request says about itself in its _meta.
type agentMeta struct {
	version  string
	caps     map[string]json.RawMessage
	client   principal.Client
	logLevel string
}

// isModern reports whether m is a request of a modern agent: its _meta
// names a protocol version.
func isModern(m *jsonrpc.Message) bool {
	if !m.IsRequest() {
		return false
	}
	var p struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	_ = json.Unmarshal(m.Params, &p)
	_, ok := p.Meta[metaProtocolVersion]
	return ok
}

// parseAgentMeta reads the protocol fields of a modern request's _meta:
// an unsupported version is UnsupportedProtocolVersion (-32022, with the
// versions the gateway speaks), missing capabilities invalid params.
func parseAgentMeta(m *jsonrpc.Message) (agentMeta, *jsonrpc.Error) {
	var p struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	_ = json.Unmarshal(m.Params, &p)
	var am agentMeta
	_ = json.Unmarshal(p.Meta[metaProtocolVersion], &am.version)
	if am.version != modernVersion {
		data, _ := json.Marshal(map[string]any{"supported": agentVersions, "requested": am.version})
		return am, &jsonrpc.Error{Code: codeUnsupportedVersion, Message: fmt.Sprintf("unsupported protocol version %q", am.version), Data: data}
	}
	if json.Unmarshal(p.Meta[metaClientCapabilities], &am.caps) != nil || am.caps == nil {
		return am, rpcError(jsonrpc.CodeInvalidParams, "invalid params: _meta lacks "+metaClientCapabilities)
	}
	if raw, ok := p.Meta[metaClientInfo]; ok && json.Unmarshal(raw, &am.client) != nil {
		return am, rpcError(jsonrpc.CodeInvalidParams, "invalid params: "+metaClientInfo+" is not an implementation")
	}
	if raw, ok := p.Meta[metaLogLevel]; ok {
		if json.Unmarshal(raw, &am.logLevel) != nil || !slices.Contains(logLevels, am.logLevel) {
			return am, rpcError(jsonrpc.CodeInvalidParams, "invalid params: unknown "+metaLogLevel)
		}
	}
	return am, nil
}

// ServeRequest serves one request of a modern agent on endpoint server
// ("all" for the aggregated one) and writes what belongs to it (progress,
// log messages, then the response) on out; it returns when the response
// is written or ctx ends (the client went away: the call is cancelled).
// header holds the request's HTTP headers (nil on other transports), for
// the Mcp-Param headers of tools/call.
func (r *Router) ServeRequest(ctx context.Context, out jsonrpc.MessageConn, p principal.Principal, server string, m *jsonrpc.Message, header http.Header) {
	r.init()
	r.reloadMu.Lock()
	var ep endpoint
	if server == "all" {
		ep = aggregatedEndpoint(r.backends())
	} else if b, ok := r.backends()[server]; ok {
		ep = singleEndpoint(b)
	} else {
		r.reloadMu.Unlock()
		_ = out.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeInvalidParams, fmt.Sprintf("mcp-gateway: unknown server %q", server)))
		return
	}
	r.reloadMu.Unlock()
	r.serveAgentRequest(ctx, ep, out, p, m, header)
}

// serveAgentRequest serves the modern request m in a request session on
// ep, writing to out.
func (r *Router) serveAgentRequest(ctx context.Context, ep endpoint, out jsonrpc.MessageConn, p principal.Principal, m *jsonrpc.Message, header http.Header) {
	if rpcErr := r.cappedRequest(m); rpcErr != nil {
		_ = out.Write(&jsonrpc.Message{JSONRPC: jsonrpc.Version, ID: m.ID, Error: rpcErr})
		return
	}
	am, rpcErr := parseAgentMeta(m)
	if rpcErr != nil {
		_ = out.Write(&jsonrpc.Message{JSONRPC: jsonrpc.Version, ID: m.ID, Error: rpcErr})
		return
	}
	p.SessionID = ""
	p.Client = am.client
	release, limitErr := r.admitAgentRequest(p, m.Method == "subscriptions/listen")
	if limitErr != nil {
		_ = out.Write(&jsonrpc.Message{JSONRPC: jsonrpc.Version, ID: m.ID, Error: limitError(limitErr)})
		return
	}
	defer release()
	s := newSession(r, ep, out, p)
	s.modern = true
	s.clientCaps = am.caps
	s.agentLevel = am.logLevel
	s.vault = r.agentVault(s)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.ctx = ctx
	defer s.release()

	reqCtx, challenge := withChallenge(withRequest(ctx, m.ID))
	result, rpcErr := s.agentRequest(reqCtx, m, header)
	if ctx.Err() != nil {
		return // cancelled: the client went away or said so
	}
	if rpcErr != nil {
		if rpcErr.Code == codeResourceNotFound {
			// MCP 2026-07-28 names an unknown resource invalid params.
			rpcErr = &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: rpcErr.Message, Data: rpcErr.Data}
		}
		_ = out.Write(challenge.mark(&jsonrpc.Message{JSONRPC: jsonrpc.Version, ID: m.ID, Error: rpcErr}))
		return
	}
	resp, err := jsonrpc.NewResult(m.ID, result)
	if err != nil {
		resp = jsonrpc.NewError(m.ID, jsonrpc.CodeInternalError, "internal error")
	}
	_ = out.Write(challenge.mark(resp))
}

// agentRequest serves a modern request and returns its result, with the
// fields MCP 2026-07-28 adds to results.
func (s *Session) agentRequest(ctx context.Context, m *jsonrpc.Message, header http.Header) (any, *jsonrpc.Error) {
	var h handler
	switch m.Method {
	case "server/discover":
		h = s.discover
	case "tools/list", "prompts/list", "resources/list", "resources/templates/list":
		h = s.list
	case "tools/call":
		h = func(ctx context.Context, m *jsonrpc.Message) (any, *jsonrpc.Error) {
			if err := s.checkParamHeaders(ctx, m, header); err != nil {
				return nil, err
			}
			return s.call(ctx, m)
		}
	case "prompts/get", "resources/read", "completion/complete":
		h = s.call
	case "subscriptions/listen":
		h = s.listen
	default:
		// Among them what MCP 2026-07-28 removed (initialize, ping,
		// logging/setLevel, resources/subscribe and unsubscribe).
		if _, legacy := s.handlers(m.Method); !legacy {
			p := s.snapshotPrincipal()
			s.r.Audit.Log(audit.Record{Sub: p.Sub, Action: m.Method, Effect: string(pep.Deny), Reason: "method not permitted"})
		}
		return nil, rpcError(jsonrpc.CodeMethodNotFound, "method not found")
	}
	result, rpcErr := h(ctx, m)
	if rpcErr != nil {
		return nil, rpcErr
	}
	return s.cacheable(m.Method, result), nil
}

// cacheable adds resultType and, for lists, reads and discovery, ttlMs
// and cacheScope: results are filtered per principal, so never public;
// aggregated lists are sorted by name.
func (s *Session) cacheable(method string, result any) any {
	var res map[string]json.RawMessage
	raw, err := json.Marshal(result)
	if err != nil || json.Unmarshal(raw, &res) != nil || res == nil {
		return result
	}
	if string(res["resultType"]) == `"input_required"` {
		return res // an interim result: nothing to cache
	}
	res["resultType"] = json.RawMessage(`"complete"`)
	set := func(k string, v any) { res[k], _ = json.Marshal(v) }
	switch method {
	case "tools/list", "prompts/list", "resources/list", "resources/templates/list", "server/discover":
		set("cacheScope", "private")
		set("ttlMs", s.r.listTTL().Milliseconds())
		if spec, ok := listSpecs[method]; ok && s.endpoint().aggregated {
			var items []map[string]json.RawMessage
			if json.Unmarshal(res[spec.field], &items) == nil {
				slices.SortStableFunc(items, func(a, b map[string]json.RawMessage) int {
					return compareRaw(a[spec.key], b[spec.key])
				})
				set(spec.field, items)
			}
		}
	case "resources/read":
		set("cacheScope", "private")
		var ttl int64
		if json.Unmarshal(res["ttlMs"], &ttl) != nil || ttl < 0 {
			ttl = 0
		}
		set("ttlMs", ttl)
	}
	return res
}

func compareRaw(a, b json.RawMessage) int {
	var x, y string
	_ = json.Unmarshal(a, &x)
	_ = json.Unmarshal(b, &y)
	switch {
	case x < y:
		return -1
	case x > y:
		return 1
	}
	return 0
}

// listTTL is ttlMs for lists: http.list_ttl, but 0 for a while after a
// policy or definition change, so that clients list again soon.
func (r *Router) listTTL() time.Duration {
	ttl := r.settings().ListTTL
	if last, ok := r.lastChange.Load().(time.Time); ok && time.Since(last) < ttl {
		return 0
	}
	return ttl
}

// discover answers server/discover: the versions the gateway speaks
// toward agents per request, the capabilities the endpoint offers (as
// initialize does), its identity and instructions.
func (s *Session) discover(ctx context.Context, m *jsonrpc.Message) (any, *jsonrpc.Error) {
	init, rpcErr := s.initialize(ctx, &jsonrpc.Message{JSONRPC: jsonrpc.Version, ID: m.ID, Method: "initialize",
		Params: json.RawMessage(`{"protocolVersion":"` + protocolVersion + `"}`)})
	if rpcErr != nil {
		return nil, rpcErr
	}
	res, _ := init.(map[string]any)
	// Changes and subscribed resources come on subscriptions/listen.
	caps := res["capabilities"]
	info := res["serverInfo"]
	if info == nil {
		info = map[string]any{"name": "mcp-gateway", "version": version.Version}
	}
	out := map[string]any{
		"supportedVersions": []string{modernVersion},
		"capabilities":      caps,
		"_meta":             map[string]any{metaServerInfo: info},
	}
	if instr, ok := res["instructions"].(string); ok && instr != "" {
		out["instructions"] = instr
	}
	return out, nil
}

// checkParamHeaders checks a tools/call's Mcp-Name and Mcp-Param headers
// against its body (HTTP only, header not nil): a proxy in front must
// not be able to route or limit by a header that says otherwise than
// the body policy decides on.
func (s *Session) checkParamHeaders(ctx context.Context, m *jsonrpc.Message, header http.Header) *jsonrpc.Error {
	if header == nil {
		return nil
	}
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	_ = json.Unmarshal(m.Params, &p)
	server, name, ok := s.endpoint().resolveName(p.Name)
	if !ok {
		return nil // the call reports the unknown tool
	}
	params, ok := s.toolParams(ctx, server, name)
	if !ok {
		return nil
	}
	if err := mcpheader.Check(header, params, p.Arguments); err != nil {
		return rpcError(codeHeaderMismatch, err.Error())
	}
	return nil
}

// toolParams returns the x-mcp-header parameters of a server's tool, from
// its tools/list (ok false if it cannot be had).
func (s *Session) toolParams(ctx context.Context, server, name string) ([]mcpheader.Param, bool) {
	items, err := s.fetchList(ctx, server, "tools/list", listSpecs["tools/list"])
	if err != nil {
		return nil, false
	}
	for _, it := range items {
		if it.name == name {
			params, err := mcpheader.ToolParams(it.raw["inputSchema"])
			return params, err == nil
		}
	}
	return nil, false
}

// learnTools remembers what the session's calls need of a server's tools
// (annotations for policy, declared argument names): a legacy session
// has them from the client's tools/list, a request session lists them.
func (s *Session) learnTools(ctx context.Context, exposed string) {
	server, _, ok := s.endpoint().resolveName(exposed)
	if !ok {
		return
	}
	items, err := s.fetchList(ctx, server, "tools/list", listSpecs["tools/list"])
	if err != nil {
		return
	}
	s.rememberArgs("tool", items)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, it := range items {
		var a map[string]any
		_ = json.Unmarshal(it.raw["annotations"], &a)
		s.annotations[s.endpoint().exposeName(it.server, it.name)] = a
	}
}

// agentLogs reports whether a log message of the given level goes to the
// modern request s serves: only if the request asked for logs, at that
// level or above.
func (s *Session) agentLogs(params json.RawMessage) bool {
	if s.agentLevel == "" {
		return false
	}
	var p struct {
		Level string `json:"level"`
	}
	_ = json.Unmarshal(params, &p)
	return slices.Index(logLevels, p.Level) >= slices.Index(logLevels, s.agentLevel)
}

// errNoClientRequests refuses what a legacy server asks while it serves
// a modern agent's call (docs/architecture.md, section 5.11.4).
var errNoClientRequests = errors.New("the client speaks MCP 2026-07-28, which has no requests to clients")
