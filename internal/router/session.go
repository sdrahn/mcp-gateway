package router

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/pseudo"
	"github.com/sdrahn/mcp-gateway/internal/signin"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

// maxListPages bounds how many pages the gateway fetches from one backend
// for a single */list request.
const maxListPages = 100

// Backend → client requests and their policy action names (ping is
// answered by the gateway itself).
var backendRequests = map[string]string{
	"sampling/createMessage": "sampling.create",
	"elicitation/create":     "elicitation.create",
	"roots/list":             "roots.list",
}

// listSpec describes a */list method.
type listSpec struct {
	field      string // result array field
	kind       string // policy resource kind
	key        string // identifying item field
	capability string // backend capability required
	uri        bool   // key is a URI (namespaced with exposeURI)
}

var listSpecs = map[string]listSpec{
	"tools/list":               {field: "tools", kind: "tool", key: "name", capability: "tools"},
	"prompts/list":             {field: "prompts", kind: "prompt", key: "name", capability: "prompts"},
	"resources/list":           {field: "resources", kind: "resource", key: "uri", capability: "resources", uri: true},
	"resources/templates/list": {field: "resourceTemplates", kind: "resource_template", key: "uriTemplate", capability: "resources", uri: true},
}

// Session terminates one client's MCP session and routes its requests to
// backend instances (one backend, or all of them on the aggregated
// endpoint).
type Session struct {
	r      *Router
	ep     atomic.Pointer[endpoint] // replaced when the server definitions are reloaded
	client jsonrpc.MessageConn
	log    *slog.Logger
	ctx    context.Context

	nextID atomic.Int64

	mu          sync.Mutex
	principal   principal.Principal
	clientCaps  map[string]json.RawMessage
	upstreams   map[string]*upstream
	releases    map[string]func() // by server, for upstreams
	logLevel    json.RawMessage   // params of the client's last logging/setLevel
	outbound    map[string]chan *jsonrpc.Message
	inflight    map[string]context.CancelFunc
	annotations map[string]map[string]any // by exposed tool name
	declared    map[string][]string       // declared argument names, by argKey

	// vault holds the session's pseudonyms (obligation "pseudonymize");
	// they end with the session.
	vault *pseudo.Vault

	// modern marks the session of one modern agent's request (agents.go):
	// clientCaps are the request's, agentLevel its log level.
	modern     bool
	agentLevel string
	// listening is the stream of a modern agent's subscriptions/listen
	// (listen.go).
	listening *agentListen
	// initialized: the client sent initialize (a connection that only
	// carries modern requests never does, and hears nothing as a
	// session).
	initialized bool
}

func newSession(r *Router, ep endpoint, client jsonrpc.MessageConn, p principal.Principal) *Session {
	s := &Session{
		r:           r,
		client:      client,
		log:         r.Log.With("session", p.SessionID, "sub", p.Sub),
		principal:   p,
		upstreams:   map[string]*upstream{},
		releases:    map[string]func(){},
		outbound:    map[string]chan *jsonrpc.Message{},
		inflight:    map[string]context.CancelFunc{},
		annotations: map[string]map[string]any{},
		vault:       pseudo.NewVault(0),
	}
	s.ep.Store(&ep)
	return s
}

// endpoint is the session's current view of the servers.
func (s *Session) endpoint() endpoint { return *s.ep.Load() }

// Run serves the client until it disconnects or ctx ends. first, if not
// nil, is a message already read from the client.
func (s *Session) Run(ctx context.Context, first *jsonrpc.Message) error {
	ctx, cancel := context.WithCancel(ctx)
	s.ctx = ctx
	defer func() {
		s.r.unregister(s)
		cancel()
		_ = s.client.Close()
		s.release()
		s.r.Broker.EndSession(s.principal.SessionID)
	}()
	go func() {
		<-ctx.Done()
		_ = s.client.Close()
	}()

	if first != nil {
		s.dispatch(first)
	}
	for {
		m, err := s.client.Read()
		if err != nil {
			var rpcErr *jsonrpc.Error
			if errors.As(err, &rpcErr) {
				_ = s.client.Write(jsonrpc.NewError(nil, rpcErr.Code, rpcErr.Message))
				continue
			}
			return err
		}
		s.dispatch(m)
	}
}

// release lets go of the session's instances.
func (s *Session) release() {
	s.mu.Lock()
	ups, releases := s.upstreams, s.releases
	s.upstreams, s.releases = map[string]*upstream{}, map[string]func(){}
	s.mu.Unlock()
	for _, u := range ups {
		u.detach(s)
	}
	for _, release := range releases {
		release()
	}
}

func (s *Session) snapshotPrincipal() principal.Principal {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.principal
}

func (s *Session) dispatch(m *jsonrpc.Message) {
	switch {
	case m.IsResponse():
		s.mu.Lock()
		ch := s.outbound[m.Key()]
		delete(s.outbound, m.Key())
		s.mu.Unlock()
		if ch != nil {
			ch <- m
		}
	case m.IsNotification():
		s.clientNotification(m)
	case s.r.ModernAgents && isModern(m):
		s.agentRequestOnConn(m)
	case m.IsRequest():
		s.clientRequest(m)
	}
}

// agentRequestOnConn serves a modern agent's request that came on this
// connection (unix socket) in a request session of its own; the
// client's notifications/cancelled for it cancels it.
func (s *Session) agentRequestOnConn(m *jsonrpc.Message) {
	ctx, cancel := context.WithCancel(s.ctx)
	s.mu.Lock()
	s.inflight[m.Key()] = cancel
	p := s.principal
	s.mu.Unlock()
	go func() {
		defer func() {
			cancel()
			s.mu.Lock()
			delete(s.inflight, m.Key())
			s.mu.Unlock()
		}()
		s.r.serveAgentRequest(ctx, s.endpoint(), s.client, p, m, nil)
	}()
}

func (s *Session) clientNotification(m *jsonrpc.Message) {
	switch m.Method {
	case "notifications/cancelled":
		var p struct {
			RequestID json.RawMessage `json:"requestId"`
		}
		if json.Unmarshal(m.Params, &p) == nil {
			s.mu.Lock()
			cancel := s.inflight[string(p.RequestID)]
			s.mu.Unlock()
			if cancel != nil {
				cancel()
			}
		}
	case "notifications/roots/list_changed":
		s.mu.Lock()
		ups := make([]*upstream, 0, len(s.upstreams))
		for _, u := range s.upstreams {
			ups = append(ups, u)
		}
		s.mu.Unlock()
		for _, u := range ups {
			_ = u.notify(m.Method, nil)
		}
	default:
		// notifications/initialized: the gateway initialized its backends
		// itself. Anything else is dropped.
	}
}

// handler serves one client request. It returns a result, or an error to
// send instead.
type handler func(ctx context.Context, m *jsonrpc.Message) (any, *jsonrpc.Error)

func (s *Session) handlers(method string) (handler, bool) {
	switch method {
	case "initialize":
		return s.initialize, true
	case "ping":
		return func(context.Context, *jsonrpc.Message) (any, *jsonrpc.Error) { return map[string]any{}, nil }, true
	case "tools/list", "prompts/list", "resources/list", "resources/templates/list":
		return s.list, true
	case "tools/call", "prompts/get", "resources/read", "resources/subscribe",
		"resources/unsubscribe", "completion/complete":
		return s.call, true
	case "logging/setLevel":
		return s.setLevel, true
	}
	return nil, false
}

func (s *Session) clientRequest(m *jsonrpc.Message) {
	h, ok := s.handlers(m.Method)
	if !ok && m.Method == "server/discover" {
		// Clients of MCP 2026-07-28 probe for it before falling back to
		// initialize: negotiation, not a refused operation, so not audited.
		_ = s.client.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeMethodNotFound, "method not found"))
		return
	}
	if !ok {
		p := s.snapshotPrincipal()
		s.r.Audit.Log(audit.Record{Session: p.SessionID, Sub: p.Sub, Action: m.Method,
			Effect: string(pep.Deny), Reason: "method not permitted"})
		_ = s.client.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeMethodNotFound, "method not permitted by gateway"))
		return
	}
	ctx, cancel := context.WithCancel(withRequest(s.ctx, m.ID))
	s.mu.Lock()
	s.inflight[m.Key()] = cancel
	s.mu.Unlock()
	// Requests may wait for backends or humans; serve them concurrently.
	go func() {
		defer func() {
			cancel()
			s.mu.Lock()
			delete(s.inflight, m.Key())
			s.mu.Unlock()
		}()
		result, rpcErr := h(ctx, m)
		if ctx.Err() != nil {
			return // cancelled by the client or the session ended
		}
		if rpcErr != nil {
			_ = s.client.Write(&jsonrpc.Message{JSONRPC: jsonrpc.Version, ID: m.ID, Error: rpcErr})
			return
		}
		resp, err := jsonrpc.NewResult(m.ID, result)
		if err != nil {
			resp = jsonrpc.NewError(m.ID, jsonrpc.CodeInternalError, "internal error")
		}
		_ = s.client.Write(resp)
	}()
}

func rpcError(code int, msg string) *jsonrpc.Error { return &jsonrpc.Error{Code: code, Message: msg} }

// upstream returns the session's instance of backend name, acquiring it
// from the pool on first use, and anew when the server's definition
// changed (Router.SetBackends) since the session got it.
func (s *Session) upstream(ctx context.Context, name string) (*upstream, error) {
	for {
		u, err := s.upstreamOnce(ctx, name)
		if !errors.Is(err, errDefinitionChanged) {
			return u, err
		}
	}
}

func (s *Session) upstreamOnce(ctx context.Context, name string) (*upstream, error) {
	b := s.endpoint().backends[name]
	s.mu.Lock()
	u := s.upstreams[name]
	s.mu.Unlock()
	if u != nil && u.backend != b {
		s.leave(name, u)
		u = nil
	}
	if u != nil && !u.isClosed() {
		return u, nil
	}
	if b == nil {
		return nil, fmt.Errorf("unknown server %q", name)
	}
	u, release, err := s.r.pool.acquire(ctx, b, s.snapshotPrincipal())
	var limit *LimitError
	if errors.As(err, &limit) {
		s.r.refused(s.snapshotPrincipal(), limit)
		return nil, err
	}
	if err != nil {
		s.log.Error("backend unavailable", "server", name, "err", err)
		return nil, err
	}
	s.mu.Lock()
	if cur := s.upstreams[name]; cur != nil && !cur.isClosed() && cur.backend == b {
		s.mu.Unlock()
		release()
		return cur, nil
	}
	if old := s.releases[name]; old != nil {
		defer old() // a closed instance, or one of an older definition
	}
	if cur := s.upstreams[name]; cur != nil {
		defer cur.leave(s)
	}
	s.upstreams[name] = u
	s.releases[name] = release
	level := s.logLevel
	s.mu.Unlock()
	u.attach(s)
	if level != nil && u.init.has("logging") {
		_, _ = u.request(ctx, s, "logging/setLevel", level)
	}
	return u, nil
}

// leave lets go of the session's instance u of backend name, whose
// definition changed: the pool stops it when no session uses it and no
// call is in flight on it. Calls of this session still running on it
// are answered as usual.
func (s *Session) leave(name string, u *upstream) {
	s.mu.Lock()
	if s.upstreams[name] != u {
		s.mu.Unlock()
		return
	}
	delete(s.upstreams, name)
	release := s.releases[name]
	delete(s.releases, name)
	s.mu.Unlock()
	u.leave(s)
	if release != nil {
		release()
	}
}

// requestKey is the context key of the client request being served.
type requestKey struct{}

// withRequest marks ctx as serving the client's request id.
func withRequest(ctx context.Context, id json.RawMessage) context.Context {
	return context.WithValue(ctx, requestKey{}, id)
}

// requestOf returns the client request ctx serves, nil if none.
func requestOf(ctx context.Context) json.RawMessage {
	id, _ := ctx.Value(requestKey{}).(json.RawMessage)
	return id
}

// requestElicitor is the session as the broker's Elicitor for one client
// request: what it sends belongs to that request (its HTTP stream).
type requestElicitor struct {
	*Session
	req json.RawMessage
}

// Notify implements broker.Elicitor.
func (e requestElicitor) Notify(method string, params any) { e.notifyRelated(method, params, e.req) }

// Elicit implements broker.Elicitor.
func (e requestElicitor) Elicit(ctx context.Context, p any) (broker.ElicitResult, error) {
	return e.elicitRelated(ctx, p, e.req)
}

// --- initialize ---------------------------------------------------------

func (s *Session) initialize(ctx context.Context, m *jsonrpc.Message) (any, *jsonrpc.Error) {
	var p struct {
		ProtocolVersion string                     `json:"protocolVersion"`
		Capabilities    map[string]json.RawMessage `json:"capabilities"`
		ClientInfo      principal.Client           `json:"clientInfo"`
	}
	if err := json.Unmarshal(m.Params, &p); err != nil {
		return nil, rpcError(jsonrpc.CodeInvalidParams, "invalid params")
	}
	s.mu.Lock()
	s.clientCaps = p.Capabilities
	s.principal.Client = p.ClientInfo
	s.initialized = !s.modern
	s.mu.Unlock()

	v := protocolVersion
	if supportedVersions[p.ProtocolVersion] {
		v = p.ProtocolVersion
	}
	if !s.endpoint().aggregated {
		server := s.endpoint().order[0]
		b := s.endpoint().backends[server]
		var init initResult
		var err error
		if b == nil || !s.mustSignIn(b) {
			init, err = s.backendInit(ctx, server)
		}
		if (b != nil && s.mustSignIn(b)) || errors.Is(err, signin.ErrNotSignedIn) {
			// Until the principal signed in, the gateway answers for
			// the server: it offers sign_in, and lists change after.
			return map[string]any{"protocolVersion": v, "serverInfo": map[string]any{"name": server},
				"capabilities": map[string]any{
					"tools":     map[string]any{"listChanged": true},
					"prompts":   map[string]any{"listChanged": true},
					"resources": map[string]any{"listChanged": true},
				}}, nil
		}
		if err != nil {
			return nil, unavailable(err)
		}
		res := map[string]any{"protocolVersion": v, "capabilities": withListChanged(init.Capabilities), "serverInfo": init.ServerInfo}
		if init.Instructions != "" {
			res["instructions"] = init.Instructions
		}
		return res, nil
	}
	return map[string]any{
		"protocolVersion": v,
		"capabilities": map[string]any{
			"tools":       map[string]any{"listChanged": true},
			"prompts":     map[string]any{"listChanged": true},
			"resources":   map[string]any{"subscribe": true, "listChanged": true},
			"completions": map[string]any{},
			"logging":     map[string]any{},
		},
		"serverInfo":   map[string]any{"name": "mcp-gateway", "version": version.Version},
		"instructions": aggregatedInstructions(s.endpoint()),
	}, nil
}

// aggregatedInstructions tells the client how names are prefixed and,
// when the shipped diagnostics servers are there, where the gateway's
// own configuration and documentation are: agents asked about the
// gateway otherwise try to read its files through other servers, which
// may not read them.
func aggregatedInstructions(ep endpoint) string {
	out := "This server aggregates several MCP servers. Tool and prompt names are " +
		"prefixed with \"<server>" + nameSep + "\", resource URIs with \"" + uriPrefix + "<server>:\"."
	if ep.backends["gateway-admin"] != nil {
		out += " The gateway's own configuration (gateway.yaml, server definitions, role data) is not meant to be " +
			"read through other servers' file tools: read it with gateway-admin" + nameSep + "show_config, check it with " +
			"gateway-admin" + nameSep + "check_config, and diagnose problems with gateway-admin" + nameSep + "doctor."
	}
	if ep.backends["gateway-docs"] != nil {
		out += " The gateway's documentation, for the installed version, is on the server gateway-docs."
	}
	return out
}

// gatewayCapabilities are the server capabilities the gateway implements
// and passes on from a backend; others (tasks, experimental features)
// would let a client use methods the gateway does not route or results
// it does not see (and cannot apply obligations to).
var gatewayCapabilities = map[string]bool{"tools": true, "prompts": true, "resources": true, "completions": true, "logging": true}

// withListChanged returns the backend's capabilities with listChanged set
// for tools, prompts and resources: the gateway notifies clients when
// policy changes what they may see, whatever the backend supports.
func withListChanged(caps map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(caps))
	for k, v := range caps {
		if !gatewayCapabilities[k] {
			continue
		}
		out[k] = v
		if k != "tools" && k != "prompts" && k != "resources" {
			continue
		}
		var c map[string]any
		if json.Unmarshal(v, &c) != nil || c == nil {
			c = map[string]any{}
		}
		c["listChanged"] = true
		if b, err := json.Marshal(c); err == nil {
			out[k] = b
		}
	}
	return out
}

// listChanged tells the client that what it may see may have changed.
func (s *Session) listChanged() {
	if s.modern {
		s.listChangedOn(allLists...)
		return
	}
	s.mu.Lock()
	initialized := s.initialized
	s.mu.Unlock()
	if !initialized {
		return
	}
	for _, m := range []string{"notifications/tools/list_changed", "notifications/prompts/list_changed",
		"notifications/resources/list_changed"} {
		_ = s.client.Write(&jsonrpc.Message{JSONRPC: jsonrpc.Version, Method: m})
	}
}

// --- */list -------------------------------------------------------------

type listItem struct {
	server string
	name   string
	raw    map[string]json.RawMessage
	// signIn marks the tool sign_in of a server the principal must sign
	// in to.
	signIn bool
}

func (s *Session) list(ctx context.Context, m *jsonrpc.Message) (any, *jsonrpc.Error) {
	spec := listSpecs[m.Method]
	var items []listItem
	for _, server := range s.endpoint().order {
		got, err := s.fetchList(ctx, server, m.Method, spec)
		if err != nil {
			if !s.endpoint().aggregated {
				return nil, rpcError(jsonrpc.CodeInternalError, "backend unavailable")
			}
			s.log.Warn("listing failed; skipping server", "server", server, "method", m.Method, "err", err)
			continue
		}
		items = append(items, got...)
	}

	s.rememberArgs(spec.kind, items)
	resources := make([]pep.Resource, len(items))
	for i, it := range items {
		resources[i] = pep.Resource{Server: it.server, Kind: spec.kind, Name: it.name, Privileged: s.r.privileged(it.server), SignIn: it.signIn}
	}
	type key struct{ server, kind, name string }
	visible := map[key]bool{}
	if len(resources) > 0 {
		vs, err := s.r.PDP.Visible(ctx, s.snapshotPrincipal(), resources)
		if err != nil {
			s.log.Warn("filtering failed; hiding everything", "method", m.Method, "err", err)
		}
		for _, r := range vs {
			visible[key{r.Server, r.Kind, r.Name}] = true
		}
	}

	out := make([]map[string]json.RawMessage, 0, len(items))
	annotations := map[string]map[string]any{}
	for _, it := range items {
		if !visible[key{it.server, spec.kind, it.name}] {
			continue
		}
		exposed := s.endpoint().exposeName(it.server, it.name)
		if spec.uri {
			exposed = s.endpoint().exposeURI(it.server, it.name)
		}
		b, _ := json.Marshal(exposed)
		it.raw[spec.key] = b
		if spec.kind == "tool" {
			var a map[string]any
			_ = json.Unmarshal(it.raw["annotations"], &a)
			annotations[exposed] = a
		}
		out = append(out, it.raw)
	}
	if spec.kind == "tool" {
		s.mu.Lock()
		s.annotations = annotations
		s.mu.Unlock()
	}
	return map[string]any{spec.field: out}, nil
}

// fetchList returns all items of one backend's list, following cursors.
func (s *Session) fetchList(ctx context.Context, server, method string, spec listSpec) ([]listItem, error) {
	if b := s.endpoint().backends[server]; b != nil && s.mustSignIn(b) {
		// Until the principal signed in, the server offers one tool:
		// signing in.
		if method == "tools/list" {
			return []listItem{signInItem(server)}, nil
		}
		return nil, nil
	}
	if b := s.endpoint().backends[server]; b != nil && b.Discovery == config.DiscoveryShared && sharedMethods[method] {
		items, err := s.r.sharedList(ctx, b, method, spec)
		if err == nil {
			return items, nil
		}
		s.log.Warn("shared discovery failed; listing from the session's instance", "server", server, "method", method, "err", err)
	}
	if b := s.endpoint().backends[server]; b != nil && b.Discovery == config.DiscoveryShared && !sharedMethods[method] {
		// A list only the principal's instance gives (resources/list):
		// ask only servers that offer it, as the shared discovery
		// instance tells, so that listing does not start the principal's
		// instance of every server.
		if init, err := s.r.sharedInit(ctx, b); err == nil && !init.has(spec.capability) {
			return nil, nil
		}
	}
	u, err := s.upstream(ctx, server)
	if err != nil {
		return nil, err
	}
	return fetchPages(ctx, u, s, server, method, spec)
}

// fetchPages fetches all pages of a list from u (for session s, nil for
// the gateway's own requests).
func fetchPages(ctx context.Context, u *upstream, s *Session, server, method string, spec listSpec) ([]listItem, error) {
	if !u.init.has(spec.capability) {
		return nil, nil
	}
	var items []listItem
	cursor := ""
	for page := 0; page < maxListPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		resp, err := u.request(ctx, s, method, params)
		if err != nil {
			return nil, err
		}
		if resp.Error != nil {
			return nil, resp.Error
		}
		var res map[string]json.RawMessage
		if err := json.Unmarshal(resp.Result, &res); err != nil {
			return nil, err
		}
		var raws []map[string]json.RawMessage
		if err := json.Unmarshal(res[spec.field], &raws); err != nil && len(res[spec.field]) > 0 {
			return nil, err
		}
		for _, raw := range raws {
			var name string
			if json.Unmarshal(raw[spec.key], &name) != nil || name == "" {
				continue
			}
			items = append(items, listItem{server: server, name: name, raw: raw})
		}
		cursor = ""
		_ = json.Unmarshal(res["nextCursor"], &cursor)
		if cursor == "" {
			return items, nil
		}
	}
	return items, nil
}

// --- enforced calls -----------------------------------------------------

// callTarget is what an enforced request addresses.
type callTarget struct {
	server   string
	resource pep.Resource
	action   string
	args     map[string]any
	// rewrite puts the backend's name/URI back into the params.
	rewrite func(params map[string]json.RawMessage)
	// progress is the progress the client asked for, if it did.
	progress *clientProgress
}

func (s *Session) target(method string, params map[string]json.RawMessage) (*callTarget, *jsonrpc.Error) {
	str := func(raw json.RawMessage) string {
		var v string
		_ = json.Unmarshal(raw, &v)
		return v
	}
	set := func(params map[string]json.RawMessage, key, v string) {
		b, _ := json.Marshal(v)
		params[key] = b
	}
	invalid := rpcError(jsonrpc.CodeInvalidParams, "invalid params")
	notFound := func(what string) *jsonrpc.Error {
		return rpcError(jsonrpc.CodeInvalidParams, "unknown "+what)
	}

	switch method {
	case "tools/call", "prompts/get":
		server, name, ok := s.endpoint().resolveName(str(params["name"]))
		if !ok {
			return nil, notFound("tool or prompt")
		}
		t := &callTarget{server: server, rewrite: func(p map[string]json.RawMessage) { set(p, "name", name) }}
		var args map[string]any
		if raw, ok := params["arguments"]; ok && json.Unmarshal(raw, &args) != nil {
			return nil, invalid
		}
		t.args = args
		if method == "tools/call" {
			exposed := str(params["name"])
			s.mu.Lock()
			ann := s.annotations[exposed]
			s.mu.Unlock()
			t.action, t.resource = "tools.call", pep.Resource{Server: server, Kind: "tool", Name: name, Annotations: ann}
			if b := s.endpoint().backends[server]; name == signInTool && b != nil && s.mustSignIn(b) {
				t.resource.Annotations, t.resource.SignIn = nil, true
			}
		} else {
			t.action, t.resource = "prompts.get", pep.Resource{Server: server, Kind: "prompt", Name: name}
		}
		return t, nil

	case "resources/read", "resources/subscribe", "resources/unsubscribe":
		server, uri, ok := s.endpoint().resolveURI(str(params["uri"]))
		if !ok {
			return nil, notFound("resource")
		}
		actions := map[string]string{"resources/read": "resources.read", "resources/subscribe": "resources.subscribe", "resources/unsubscribe": "resources.unsubscribe"}
		return &callTarget{server: server, action: actions[method],
			resource: pep.Resource{Server: server, Kind: "resource", Name: uri},
			rewrite:  func(p map[string]json.RawMessage) { set(p, "uri", uri) }}, nil

	case "completion/complete":
		var ref map[string]json.RawMessage
		if json.Unmarshal(params["ref"], &ref) != nil {
			return nil, invalid
		}
		t := &callTarget{action: "completion.complete"}
		switch str(ref["type"]) {
		case "ref/prompt":
			server, name, ok := s.endpoint().resolveName(str(ref["name"]))
			if !ok {
				return nil, notFound("prompt")
			}
			t.server, t.resource = server, pep.Resource{Server: server, Kind: "prompt", Name: name}
			t.rewrite = func(p map[string]json.RawMessage) {
				set(ref, "name", name)
				p["ref"], _ = json.Marshal(ref)
			}
		case "ref/resource":
			server, uri, ok := s.endpoint().resolveURI(str(ref["uri"]))
			if !ok {
				return nil, notFound("resource template")
			}
			t.server, t.resource = server, pep.Resource{Server: server, Kind: "resource_template", Name: uri}
			t.rewrite = func(p map[string]json.RawMessage) {
				set(ref, "uri", uri)
				p["ref"], _ = json.Marshal(ref)
			}
		default:
			return nil, invalid
		}
		return t, nil
	}
	return nil, invalid
}

func (s *Session) call(ctx context.Context, m *jsonrpc.Message) (any, *jsonrpc.Error) {
	// Policy decides on the parameters as the gateway decodes them; the
	// server must not be able to read them differently.
	if err := jsonrpc.CheckKeys(m.Params); err != nil {
		return nil, rpcError(jsonrpc.CodeInvalidParams, "invalid params: "+err.Error())
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(m.Params, &params); err != nil {
		return nil, rpcError(jsonrpc.CodeInvalidParams, "invalid params")
	}
	if err := checkParamKeys(params); err != nil {
		return nil, rpcError(jsonrpc.CodeInvalidParams, "invalid params: "+err.Error())
	}
	// A modern agent's call that may ask for input is a round of a multi
	// round-trip request (mrtr.go).
	var round *agentRound
	if s.modern && inputMethods[m.Method] {
		var rpcErr *jsonrpc.Error
		if round, rpcErr = s.agentRoundOf(m.Method, params); rpcErr != nil {
			return nil, rpcErr
		}
	}
	if s.modern && m.Method == "tools/call" {
		var name string
		_ = json.Unmarshal(params["name"], &name)
		s.learnTools(ctx, name)
	}
	t, rpcErr := s.target(m.Method, params)
	if rpcErr != nil {
		return nil, rpcErr
	}
	if err := s.checkArgNames(ctx, t); err != nil {
		return nil, rpcError(jsonrpc.CodeInvalidParams, "invalid params: "+err.Error())
	}
	t.progress = s.progressOf(ctx, params)

	decisionID := newDecisionID()
	var dec pep.Decision
	var grantID string
	var in pep.Input
	if s.modern {
		var ask any
		if dec, grantID, in, ask = s.decideModern(ctx, t, decisionID, round); ask != nil {
			return ask, nil
		}
	} else {
		dec, grantID, in = s.decide(ctx, t, decisionID)
	}
	p := s.snapshotPrincipal()
	// Obligations were validated by pep.Evaluate; a compile error here
	// cannot happen, but would deny.
	ob, err := dec.Obligations.Compile()
	if err != nil {
		dec = pep.Decision{Effect: pep.Deny, Reason: "invalid obligations"}
	}
	var reidentified []string
	nReidentified := 0
	if dec.Effect == pep.Allow && len(ob.Reidentify) > 0 {
		dec, ob, reidentified, nReidentified = s.reidentify(ctx, t, in, dec, ob)
	}
	if dec.Effect == pep.Allow {
		if err := ob.CheckArgs(t.args); err != nil {
			dec = pep.Decision{Effect: pep.Deny, Reason: err.Error()}
		} else if !round.laterServerRound() && !s.r.limiter.Allow(rateKey(p, t), ob.Rates) {
			// (A server's input rounds are one call.)
			dec = pep.Decision{Effect: pep.Deny, Reason: "rate limit exceeded"}
		}
	}
	s.r.Audit.Log(audit.Record{Session: p.SessionID, Sub: p.Sub, Action: t.action, Server: t.server,
		Name: t.resource.Name, Effect: string(dec.Effect), Reason: dec.Reason, GrantID: grantID,
		DecisionID: decisionID, Args: t.args, FullArgs: ob != nil && ob.FullAudit, Reidentified: nReidentified,
		Privileged: s.r.privileged(t.server), Scopes: p.Scopes, OutsideScopes: dec.OutsideScopes})
	if dec.Effect != pep.Allow {
		return s.denial(m.Method, dec.Reason)
	}
	if len(reidentified) > 0 {
		if err := setArguments(params, t.args, reidentified); err != nil {
			return nil, rpcError(jsonrpc.CodeInternalError, "internal error")
		}
	}

	b := s.endpoint().backends[t.server]
	if b != nil && s.mustSignIn(b) {
		if s.modern {
			if ok, res, rerr := s.signInModern(ctx, m.Method, b, round); !ok {
				return res, rerr
			}
		} else if err := s.signIn(ctx, b); err != nil {
			return s.signInFailed(m.Method, t.server, err)
		}
		if m.Method == "tools/call" && t.resource.Name == signInTool {
			return textResult("Signed in to " + t.server + ". List the tools again to see its tools."), nil
		}
	}
	u, err := s.upstream(ctx, t.server)
	if errors.Is(err, signin.ErrTokenRejected) {
		// The server refused the token at once: start with a refreshed one.
		u, err = s.upstream(ctx, t.server)
	}
	if errors.Is(err, signin.ErrNotSignedIn) && b != nil && b.SignIn != nil && s.r.SignIns != nil {
		// The tokens were refused at refresh: sign in again.
		if s.modern {
			if ok, res, rerr := s.signInModern(ctx, m.Method, b, round); !ok {
				return res, rerr
			}
		} else if err := s.signIn(ctx, b); err != nil {
			return s.signInFailed(m.Method, t.server, err)
		}
		u, err = s.upstream(ctx, t.server)
	}
	if err != nil {
		return nil, unavailable(err)
	}
	t.rewrite(params)
	// A task-augmented request (params.task, MCP 2025-11-25) would make the
	// backend answer with a task to poll through methods the gateway does
	// not route; it runs synchronously instead. The gateway does not offer
	// tasks, but some clients ask regardless.
	delete(params, "task")
	// The answers to a modern server's input requests are the gateway's
	// to give, after policy (answerInput): a client cannot supply them.
	delete(params, "inputResponses")
	delete(params, "requestState")
	if gw := s.rewriteProgressToken(u, params, t.progress.offset(), requestOf(ctx)); gw != nil {
		defer u.unregisterProgress(gw)
	}
	send := func() (json.RawMessage, bool, *jsonrpc.Error) {
		resp, err := u.request(ctx, s, m.Method, params)
		if errors.Is(err, errShuttingDown) {
			return nil, false, rpcError(jsonrpc.CodeInternalError, err.Error())
		}
		if err != nil {
			return nil, false, rpcError(jsonrpc.CodeInternalError, "backend unavailable")
		}
		if resp.Error != nil {
			if b != nil && b.SignIn != nil && s.r.SignIns != nil && strings.Contains(resp.Error.Message, signin.RejectedMarker) {
				// The instance ends; the next call starts one with a
				// refreshed token.
				s.r.SignIns.Rejected(t.server, s.snapshotPrincipal())
			}
			return nil, false, resp.Error
		}
		raw, inputRequired := completeResult(resp.Result)
		return raw, inputRequired, nil
	}
	// A retry of a modern agent's call that answers a modern server's
	// input requests: the answers and the server's state go back to it.
	inputRound := round.serverRound(t.server, params)
	raw, inputRequired, rerr := send()
	// A modern server asks the client for input with a result instead of
	// requests (multi round-trip). A legacy client is asked over its
	// session, each request decided as a server's request is, and the
	// call is made again with the answers: the client sees one call. A
	// modern agent gets the requests policy allows with the gateway's
	// state and calls again itself.
	for ; inputRequired && rerr == nil; inputRound++ {
		if inputRound == maxInputRounds {
			return nil, rpcError(jsonrpc.CodeInternalError, fmt.Sprintf("%s asked the client for input more than %d times in one call", t.server, maxInputRounds))
		}
		if round != nil {
			var ask any
			var again bool
			if ask, again, rerr = s.forwardInput(round, u, raw, inputRound+1, params); rerr == nil && !again {
				return ask, nil
			}
		} else if s.modern {
			return nil, rpcError(jsonrpc.CodeInternalError, t.server+" asks for input, which a "+m.Method+" request of MCP 2026-07-28 cannot pass on")
		} else {
			rerr = s.answerInput(ctx, u, raw, params)
		}
		if rerr == nil {
			raw, inputRequired, rerr = send()
		}
	}
	if rerr != nil {
		return nil, rerr
	}
	result, stats, err := ob.ApplyOutput(raw, s.vault)
	if len(stats) > 0 {
		s.auditPseudonymized(p, t.server, t.resource.Name, decisionID, stats)
	}
	if err != nil {
		s.r.Audit.Log(audit.Record{Session: p.SessionID, Sub: p.Sub, Action: t.action, Server: t.server,
			Name: t.resource.Name, Effect: string(pep.Deny), Reason: "output withheld: " + err.Error(),
			DecisionID: decisionID})
		return s.denial(m.Method, "output withheld: "+err.Error())
	}
	if m.Method == "resources/read" && s.endpoint().aggregated {
		return s.exposeContents(t.server, result), nil
	}
	return result, nil
}

// rateKey identifies the counter for rate-limit obligations: per
// principal, action and target.
func rateKey(p principal.Principal, t *callTarget) string {
	return strings.Join([]string{string(p.Transport), p.Issuer, p.Sub, t.action, t.server, t.resource.Name}, "\x00")
}

// decide evaluates policy for t, obtaining an approval if policy asks.
// decisionID goes into the policy input to correlate OPA's decision log
// with the audit record.
// It also returns the policy input of the final decision (with the grants
// it was made with).
func (s *Session) decide(ctx context.Context, t *callTarget, decisionID string) (pep.Decision, string, pep.Input) {
	p := s.snapshotPrincipal()
	in := pep.Input{
		Principal: p,
		Action:    t.action,
		Resource:  t.resource,
		Args:      t.args,
		Grants:    s.r.Broker.Grants(p, t.resource.Server, t.resource.Name),
		Context:   s.policyContext(decisionID),
	}
	in.Resource.Privileged = s.r.privileged(t.resource.Server)
	// A "once" grant from an approval decided while no call was waiting
	// (the client left, the gateway restarted) is used up by the call it
	// allows.
	once, haveOnce := s.r.Broker.TakeOnce(p, t.resource.Server, t.resource.Name)
	if haveOnce {
		in.Grants = append(in.Grants, once)
	}
	dec := pep.Evaluate(ctx, s.r.PDP, in)
	if haveOnce {
		if dec.Effect == pep.Allow {
			return dec, once.ID, in
		}
		s.r.Broker.ReturnOnce(once)
		in.Grants = in.Grants[:len(in.Grants)-1]
	}
	if dec.Effect != pep.Ask {
		return dec, "", in
	}
	ask := *dec.Ask
	if p.SessionID == "" {
		// No session (a modern agent's request): no grant for the
		// session, which would hold for all of them.
		ask.Scopes = slices.DeleteFunc(slices.Clone(ask.Scopes), func(sc string) bool { return sc == "session" })
	}
	stop := s.reportWaiting(t)
	g, err := s.r.Broker.Approve(ctx, requestElicitor{s, requestOf(ctx)}, in, ask)
	stop()
	switch {
	case errors.Is(err, broker.ErrNoChannel):
		return pep.Decision{Effect: pep.Deny, Reason: fmt.Sprintf("approval via %s required but not available", dec.Ask.Channel)}, "", in
	case err != nil:
		s.log.Warn("approval failed", "err", err)
		return pep.Decision{Effect: pep.Deny, Reason: "approval failed"}, "", in
	case g == nil:
		return pep.Decision{Effect: pep.Deny, Reason: "declined by user"}, "", in
	}
	// Stored grants now include g, unless it is a "once" grant, which is
	// only valid for this re-evaluation.
	in.Grants = s.r.Broker.Grants(p, t.resource.Server, t.resource.Name)
	if g.Scope == "once" {
		in.Grants = append(in.Grants, *g)
	}
	dec = pep.Evaluate(ctx, s.r.PDP, in)
	if dec.Effect == pep.Ask {
		dec = pep.Decision{Effect: pep.Deny, Reason: "policy did not accept the approval"}
	}
	return dec, g.ID, in
}

// reidentify replaces the session's pseudonyms in the arguments that the
// obligation "reidentify" names by the original values, and asks policy
// again with the arguments as they will be forwarded: the decision (and
// its obligations) must hold for the real values too. It returns the
// decision to enforce, its obligations, the arguments changed and the
// number of pseudonyms replaced.
func (s *Session) reidentify(ctx context.Context, t *callTarget, in pep.Input, dec pep.Decision, ob *pep.Compiled) (pep.Decision, *pep.Compiled, []string, int) {
	args, changed, n := s.vault.Reidentify(t.args, ob.Reidentify)
	if n == 0 {
		return dec, ob, nil, 0
	}
	in.Args = args
	dec2 := pep.Evaluate(ctx, s.r.PDP, in)
	if dec2.Effect != pep.Allow {
		reason := "policy did not accept the re-identified arguments"
		if dec2.Effect == pep.Deny && dec2.Reason != "" {
			reason += ": " + dec2.Reason
		}
		return pep.Decision{Effect: pep.Deny, Reason: reason}, ob, nil, 0
	}
	ob2, err := dec2.Obligations.Compile()
	if err != nil {
		return pep.Decision{Effect: pep.Deny, Reason: "invalid obligations"}, ob, nil, 0
	}
	t.args = args
	return dec2, ob2, changed, n
}

// setArguments writes the named arguments of args into params.
func setArguments(params map[string]json.RawMessage, args map[string]any, names []string) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(params["arguments"], &raw); err != nil {
		return err
	}
	for _, name := range names {
		b, err := json.Marshal(args[name])
		if err != nil {
			return err
		}
		raw[name] = b
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	params["arguments"] = b
	return nil
}

// auditPseudonymized records what was pseudonymized (classes and counts,
// never values).
func (s *Session) auditPseudonymized(p principal.Principal, server, name, decisionID string, st pseudo.Stats) {
	s.r.Audit.Note("mcp-pseudonymize", map[string]string{
		"session": p.SessionID, "sub": p.Sub, "server": server, "name": name,
		"decision_id": decisionID, "values": st.String(),
	})
}

// unavailable is the client's error for a backend that cannot be
// reached; it tells when a failed backend will be tried again.
func unavailable(err error) *jsonrpc.Error {
	var limit *LimitError
	if errors.As(err, &limit) {
		return rpcError(jsonrpc.CodeInternalError, "mcp-gateway: "+limit.Error())
	}
	var b *BackoffError
	if errors.As(err, &b) {
		return rpcError(jsonrpc.CodeInternalError, fmt.Sprintf("backend unavailable; retry in %s", b.RetryIn.Round(time.Second)))
	}
	return rpcError(jsonrpc.CodeInternalError, "backend unavailable")
}

// signInTool is the tool a server with sign_in offers a principal who has
// not signed in to it.
const signInTool = "sign_in"

// mustSignIn reports whether the session's principal must sign in to b
// before using it.
func (s *Session) mustSignIn(b *config.Backend) bool {
	return b.SignIn != nil && s.r.SignIns != nil && !s.r.SignIns.Signed(s.snapshotPrincipal(), b.Name)
}

// signIn signs the session's principal in to b through the client.
func (s *Session) signIn(ctx context.Context, b *config.Backend) error {
	return s.r.SignIns.Run(ctx, requestElicitor{s, requestOf(ctx)}, b, s.snapshotPrincipal())
}

func signInItem(server string) listItem {
	raw := map[string]json.RawMessage{}
	raw["name"], _ = json.Marshal(signInTool)
	raw["title"], _ = json.Marshal("Sign in to " + server)
	raw["description"], _ = json.Marshal("Sign in to " + server + " with your account there to use its tools. " +
		"You are asked to open a sign-in page; the gateway keeps the token.")
	raw["inputSchema"] = json.RawMessage(`{"type":"object","properties":{}}`)
	return listItem{server: server, name: signInTool, raw: raw, signIn: true}
}

func textResult(text string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
}

func (s *Session) signInFailed(method, server string, err error) (any, *jsonrpc.Error) {
	msg := "signing in to " + server + " failed: " + err.Error()
	var le *signin.LinkError
	if errors.As(err, &le) {
		// The client cannot open the link: the agent shows it.
		msg = le.Error()
	}
	if method == "tools/call" {
		return map[string]any{
			"content": []map[string]any{{"type": "text", "text": "mcp-gateway: " + msg}},
			"isError": true,
		}, nil
	}
	return nil, rpcError(jsonrpc.CodeInternalError, "mcp-gateway: "+msg)
}

func (s *Session) denial(method, reason string) (any, *jsonrpc.Error) {
	if reason == "" {
		reason = "denied by policy"
	}
	if method == "tools/call" {
		// A tool error lets the agent see and reason about the denial.
		return map[string]any{
			"content": []map[string]any{{"type": "text", "text": "mcp-gateway: " + reason}},
			"isError": true,
		}, nil
	}
	return nil, rpcError(jsonrpc.CodeForbidden, reason)
}

// rewriteProgressToken replaces params._meta.progressToken with a token
// unique on u and returns it (nil if there was none).
// The backend's progress values are shifted by offset (see clientProgress).
func (s *Session) rewriteProgressToken(u *upstream, params map[string]json.RawMessage, offset float64, req json.RawMessage) json.RawMessage {
	var meta map[string]json.RawMessage
	if json.Unmarshal(params["_meta"], &meta) != nil {
		return nil
	}
	token, ok := meta["progressToken"]
	if !ok {
		return nil
	}
	gw := u.registerProgress(s, token, offset, req)
	meta["progressToken"] = gw
	params["_meta"], _ = json.Marshal(meta)
	return gw
}

// exposeContents namespaces the URIs in a resources/read result.
func (s *Session) exposeContents(server string, result json.RawMessage) json.RawMessage {
	var res map[string]json.RawMessage
	if json.Unmarshal(result, &res) != nil {
		return result
	}
	var contents []map[string]json.RawMessage
	if json.Unmarshal(res["contents"], &contents) != nil {
		return result
	}
	for _, c := range contents {
		var uri string
		if json.Unmarshal(c["uri"], &uri) == nil && uri != "" {
			c["uri"], _ = json.Marshal(s.endpoint().exposeURI(server, uri))
		}
	}
	res["contents"], _ = json.Marshal(contents)
	out, err := json.Marshal(res)
	if err != nil {
		return result
	}
	return out
}

// backendInit returns a backend's initialize result: the shared discovery
// instance's, so that initializing does not start the principal's
// instance, else the principal's instance's.
func (s *Session) backendInit(ctx context.Context, server string) (initResult, error) {
	if b := s.endpoint().backends[server]; b != nil && b.Discovery == config.DiscoveryShared {
		init, err := s.r.sharedInit(ctx, b)
		if err == nil {
			return init, nil
		}
		s.log.Warn("shared discovery failed; initializing the session's instance", "server", server, "err", err)
	}
	u, err := s.upstream(ctx, server)
	if err != nil {
		return initResult{}, err
	}
	return u.init, nil
}

// setLevel passes the log level to the session's running instances and
// remembers it for instances started later (without starting any).
func (s *Session) setLevel(ctx context.Context, m *jsonrpc.Message) (any, *jsonrpc.Error) {
	s.mu.Lock()
	s.logLevel = m.Params
	ups := make([]*upstream, 0, len(s.upstreams))
	for _, u := range s.upstreams {
		ups = append(ups, u)
	}
	s.mu.Unlock()
	for _, u := range ups {
		if !u.isClosed() && u.init.has("logging") {
			_, _ = u.request(ctx, s, m.Method, m.Params)
		}
	}
	return map[string]any{}, nil
}

// newDecisionID returns a random id for one enforcement decision.
func newDecisionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (s *Session) policyContext(decisionID string) pep.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	caps := map[string]any{}
	for k, v := range s.clientCaps {
		var x any
		if json.Unmarshal(v, &x) == nil {
			caps[k] = x
		}
	}
	pc := pep.Context{
		Time:               time.Now().UTC().Format(time.RFC3339),
		Transport:          s.principal.Transport,
		DecisionID:         decisionID,
		ClientCapabilities: caps,
	}
	if s.modern {
		pc.ProtocolVersion = modernVersion
	}
	return pc
}

// --- notifications and requests from backends ---------------------------

// upstreamNotification passes on a notification of u; req is the client
// request it belongs to, if known (nil: none).
func (s *Session) upstreamNotification(u *upstream, m *jsonrpc.Message, req json.RawMessage) {
	if s.modern {
		// A modern request gets the log messages it asked for, a listener
		// the updates of the resources it subscribed to; list changes
		// reach listeners from the router (backendListChanged).
		switch {
		case m.Method == "notifications/resources/updated":
			s.resourceUpdated(u, m)
			return
		case m.Method != "notifications/message" || !s.agentLogs(m.Params):
			return
		}
	}
	switch m.Method {
	case "notifications/resources/updated":
		var p map[string]json.RawMessage
		var uri string
		if json.Unmarshal(m.Params, &p) != nil || json.Unmarshal(p["uri"], &uri) != nil {
			return
		}
		// The subscription was decided when it was made; access may have
		// been revoked since, and then the client hears no more about the
		// resource (docs/architecture.md, decision D12).
		if !s.stillAllowed(u.backend.Name, "resources.subscribe", pep.Resource{Server: u.backend.Name, Kind: "resource", Name: uri}) {
			return
		}
		p["uri"], _ = json.Marshal(s.endpoint().exposeURI(u.backend.Name, uri))
		params, _ := json.Marshal(p)
		_ = s.client.Write(&jsonrpc.Message{JSONRPC: jsonrpc.Version, Method: m.Method, Params: params})
	case "notifications/message":
		if !s.endpoint().aggregated {
			_ = jsonrpc.WriteRelated(s.client, m, req)
			return
		}
		var p map[string]json.RawMessage
		if json.Unmarshal(m.Params, &p) != nil {
			return
		}
		logger := u.backend.Name
		var l string
		if json.Unmarshal(p["logger"], &l) == nil && l != "" {
			logger += "/" + l
		}
		p["logger"], _ = json.Marshal(logger)
		params, _ := json.Marshal(p)
		_ = jsonrpc.WriteRelated(s.client, &jsonrpc.Message{JSONRPC: jsonrpc.Version, Method: m.Method, Params: params}, req)
	default: // */list_changed
		_ = s.client.Write(m)
	}
}

// stillAllowed asks policy whether the principal may still do action on
// r, for what a server sends after an earlier decision; anything but an
// allow (an error, a deny, an ask) is no.
func (s *Session) stillAllowed(server, action string, r pep.Resource) bool {
	r.Privileged = s.r.privileged(server)
	dec := pep.Evaluate(s.ctx, s.r.PDP, pep.Input{
		Principal: s.snapshotPrincipal(),
		Action:    action,
		Resource:  r,
		Context:   s.policyContext(newDecisionID()),
	})
	return dec.Effect == pep.Allow
}

// relayBackendRequest decides and relays a request from backend u to this
// session's client, and returns the response for the backend.
func (s *Session) relayBackendRequest(ctx context.Context, u *upstream, m *jsonrpc.Message, req json.RawMessage) *jsonrpc.Message {
	p := s.snapshotPrincipal()
	if s.modern {
		// A legacy server asks a modern agent: there is no way to ask it
		// (docs/architecture.md, section 5.11.4). An elicitation is
		// declined, the others refused.
		s.r.Audit.Log(audit.Record{Sub: p.Sub, Action: m.Method, Server: u.backend.Name,
			Effect: string(pep.Deny), Reason: errNoClientRequests.Error(), Instance: u.id})
		if m.Method == "elicitation/create" {
			r, _ := jsonrpc.NewResult(m.ID, map[string]any{"action": "decline"})
			return r
		}
		return jsonrpc.NewError(m.ID, jsonrpc.CodeForbidden, errNoClientRequests.Error())
	}
	params, ok := s.admitBackendRequest(u, m.Method, m.Params)
	if !ok {
		return jsonrpc.NewError(m.ID, jsonrpc.CodeForbidden, "denied by mcp-gateway policy")
	}
	resp, err := s.requestClient(ctx, m.Method, params, req)
	if err != nil {
		var rpcErr *jsonrpc.Error
		if errors.As(err, &rpcErr) {
			return &jsonrpc.Message{JSONRPC: jsonrpc.Version, ID: m.ID, Error: rpcErr}
		}
		return jsonrpc.NewError(m.ID, jsonrpc.CodeInternalError, "client unavailable")
	}
	return &jsonrpc.Message{JSONRPC: jsonrpc.Version, ID: m.ID, Result: resp.Result}
}

// admitBackendRequest decides a server's request to the client (method,
// params) and audits it. If policy allows it, it returns the params to
// send the client: an elicitation labelled with the server's name, what
// goes to the model for sampling released as results are.
func (s *Session) admitBackendRequest(u *upstream, method string, params json.RawMessage) (json.RawMessage, bool) {
	p := s.snapshotPrincipal()
	action, known := backendRequests[method]
	dec := pep.Decision{Effect: pep.Deny, Reason: "method not permitted"}
	var args map[string]any
	if method == "elicitation/create" {
		args = elicitationArgs(params)
	}
	decisionID := newDecisionID()
	if known {
		dec = pep.Evaluate(s.ctx, s.r.PDP, pep.Input{
			Principal: p,
			Action:    action,
			Resource:  pep.Resource{Server: u.backend.Name, Kind: "client", Name: method, Privileged: u.backend.Privileged},
			Args:      args,
			Context:   s.policyContext(decisionID),
		})
	}
	s.r.Audit.Log(audit.Record{Session: p.SessionID, Sub: p.Sub, Action: method, Server: u.backend.Name,
		Effect: string(dec.Effect), Reason: dec.Reason, Instance: u.id, DecisionID: decisionID, Args: args,
		Scopes: p.Scopes, OutsideScopes: dec.OutsideScopes})
	if dec.Effect == pep.Allow && method == "sampling/createMessage" {
		// What a backend sends for sampling goes to the client's model:
		// redaction, pseudonymization and the size limit apply to it as to
		// results.
		var err error
		if params, err = s.releaseToModel(p, u.backend.Name, decisionID, dec, params); err != nil {
			s.r.Audit.Log(audit.Record{Session: p.SessionID, Sub: p.Sub, Action: method, Server: u.backend.Name,
				Effect: string(pep.Deny), Reason: "request withheld: " + err.Error(), Instance: u.id, DecisionID: decisionID})
			dec = pep.Decision{Effect: pep.Deny}
		}
	}
	if dec.Effect != pep.Allow {
		return nil, false
	}
	if method == "elicitation/create" {
		params = labelElicitation(params, u.backend.Name)
	}
	return params, true
}

// sensitiveField matches schema fields that look like they ask for
// secrets. Backends must not collect those through elicitation (the MCP
// specification forbids requesting sensitive information in form mode);
// policy can still allow it per permission ("allow_sensitive").
var sensitiveField = regexp.MustCompile(`(?i)pass(word|phrase|wd|code)|secret|token|api[-_ ]?key|` +
	`private[-_ ]?key|credential|card[-_ ]?number|(^|[^a-z])(pin|otp|2fa|mfa|totp|cvv|iban|ssn)([^a-z]|$)`)

// elicitationArgs describes a backend's elicitation for policy: its mode,
// URL (URL mode), requested field names, and whether any field looks
// like it asks for a secret (by name, title, description or format).
func elicitationArgs(params json.RawMessage) map[string]any {
	var p struct {
		Mode            string `json:"mode"`
		URL             string `json:"url"`
		RequestedSchema struct {
			Properties map[string]struct {
				Title       string `json:"title"`
				Description string `json:"description"`
				Format      string `json:"format"`
			} `json:"properties"`
		} `json:"requestedSchema"`
	}
	_ = json.Unmarshal(params, &p)
	if p.Mode == "" {
		p.Mode = "form"
	}
	fields := make([]string, 0, len(p.RequestedSchema.Properties))
	sensitive := false
	for name, f := range p.RequestedSchema.Properties {
		fields = append(fields, name)
		for _, s := range []string{name, f.Title, f.Description, f.Format} {
			if sensitiveField.MatchString(s) {
				sensitive = true
			}
		}
	}
	sort.Strings(fields)
	args := map[string]any{"mode": p.Mode, "fields": fields, "sensitive": sensitive}
	if p.URL != "" {
		args["url"] = p.URL
	}
	return args
}

// releaseToModel applies the output obligations of dec to params.
func (s *Session) releaseToModel(p principal.Principal, server, decisionID string, dec pep.Decision, params json.RawMessage) (json.RawMessage, error) {
	ob, err := dec.Obligations.Compile()
	if err != nil {
		return nil, err
	}
	out, stats, err := ob.ApplyOutput(params, s.vault)
	if len(stats) > 0 {
		s.auditPseudonymized(p, server, "sampling/createMessage", decisionID, stats)
	}
	return out, err
}

// labelElicitation prefixes a backend's elicitation message with the
// backend's name, so the user always knows who is asking.
func labelElicitation(params json.RawMessage, server string) json.RawMessage {
	var p map[string]any
	if err := json.Unmarshal(params, &p); err != nil {
		return params
	}
	msg, _ := p["message"].(string)
	p["message"] = fmt.Sprintf("[%s] %s", server, msg)
	out, err := json.Marshal(p)
	if err != nil {
		return params
	}
	return out
}

// --- requests to the client (broker.Elicitor) ---------------------------

// elicitationModes returns the elicitation modes the client declared
// (nil without the capability). A capability without modes means form
// mode (MCP before 2025-11-25).
func (s *Session) elicitationModes() map[string]json.RawMessage {
	s.mu.Lock()
	raw, ok := s.clientCaps["elicitation"]
	s.mu.Unlock()
	if !ok {
		return nil
	}
	var modes map[string]json.RawMessage
	if json.Unmarshal(raw, &modes) != nil {
		return nil
	}
	if len(modes) == 0 {
		return map[string]json.RawMessage{"form": nil}
	}
	return modes
}

// SupportsForm implements broker.Elicitor.
func (s *Session) SupportsForm() bool {
	_, ok := s.elicitationModes()["form"]
	return ok
}

// SupportsURL implements broker.Elicitor.
func (s *Session) SupportsURL() bool {
	_, ok := s.elicitationModes()["url"]
	return ok
}

// Notify implements broker.Elicitor.
func (s *Session) Notify(method string, params any) {
	s.notifyRelated(method, params, nil)
}

func (s *Session) notifyRelated(method string, params any, req json.RawMessage) {
	if n, err := jsonrpc.NewNotification(method, params); err == nil {
		if s.modern && method == "notifications/message" && !s.agentLogs(n.Params) {
			return // the request did not ask for log messages
		}
		_ = jsonrpc.WriteRelated(s.client, n, req)
	}
}

// Elicit implements broker.Elicitor.
func (s *Session) Elicit(ctx context.Context, p any) (broker.ElicitResult, error) {
	return s.elicitRelated(ctx, p, nil)
}

func (s *Session) elicitRelated(ctx context.Context, p any, req json.RawMessage) (broker.ElicitResult, error) {
	resp, err := s.requestClient(ctx, "elicitation/create", p, req)
	if err != nil {
		return broker.ElicitResult{}, err
	}
	var r broker.ElicitResult
	if err := json.Unmarshal(resp.Result, &r); err != nil {
		return broker.ElicitResult{}, err
	}
	return r, nil
}

// requestClient sends a gateway-originated request to the client, as
// belonging to the client's request req (nil: none), and waits for the
// response.
func (s *Session) requestClient(ctx context.Context, method string, params any, req json.RawMessage) (*jsonrpc.Message, error) {
	id := json.RawMessage(strconv.Quote("mcpgw-" + strconv.FormatInt(s.nextID.Add(1), 10)))
	out, err := jsonrpc.NewRequest(id, method, params)
	if err != nil {
		return nil, err
	}
	ch := make(chan *jsonrpc.Message, 1)
	s.mu.Lock()
	s.outbound[string(id)] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.outbound, string(id))
		s.mu.Unlock()
	}()
	if err := jsonrpc.WriteRelated(s.client, out, req); err != nil {
		return nil, err
	}
	select {
	case resp := <-ch:
		if resp.Error != nil {
			return nil, resp.Error
		}
		return resp, nil
	case <-ctx.Done():
		n, _ := jsonrpc.NewNotification("notifications/cancelled", map[string]any{"requestId": id, "reason": "timeout"})
		_ = jsonrpc.WriteRelated(s.client, n, req)
		return nil, ctx.Err()
	}
}
