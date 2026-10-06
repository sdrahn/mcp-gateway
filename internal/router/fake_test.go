package router

import (
	"context"
	"encoding/json"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/pseudo"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
)

// fakePDP: read_* tools allowed, write_* tools need form approval, other
// tools denied; prompts allowed; resources allowed below file:///ok/;
// resource templates visible; roots/list allowed, other backend requests
// denied.
type fakePDP struct{}

func (fakePDP) Decide(_ context.Context, in pep.Input) (pep.Decision, error) {
	allow := pep.Decision{Effect: pep.Allow}
	deny := pep.Decision{Effect: pep.Deny, Reason: "not yours"}
	switch in.Action {
	case "tools.call":
		// A token with scopes but without mcp:write: writes lie outside
		// its ceiling (§6.7).
		if p := in.Principal; p.Transport == principal.TransportHTTP && len(p.Scopes) > 0 && !slices.Contains(p.Scopes, "mcp:write") &&
			strings.HasPrefix(in.Resource.Name, "write_") {
			return pep.Decision{Effect: pep.Deny, Reason: "outside the token's scopes", OutsideScopes: true, RequiredScopes: []string{"mcp:write", "mcp:admin"}}, nil
		}
		// Policy on the arguments as forwarded (after re-identification).
		if note, _ := in.Args["note"].(string); in.Resource.Name == "update_customer" && strings.Contains(note, "forbidden@") {
			return deny, nil
		}
		if o, ok := testObligations[in.Resource.Name]; ok {
			return pep.Decision{Effect: pep.Allow, Obligations: &o}, nil
		}
		switch {
		case strings.HasPrefix(in.Resource.Name, "read_"), strings.HasPrefix(in.Resource.Name, "ask_"),
			in.Resource.Name == "slow", in.Resource.Name == "progress", in.Resource.Name == "sign_in":
			return allow, nil
		case strings.HasPrefix(in.Resource.Name, "write_"):
			if len(in.Grants) > 0 {
				return allow, nil
			}
			return pep.Decision{Effect: pep.Ask, Ask: &pep.AskSpec{Channel: pep.ChannelForm, Scopes: []string{"once", "session"}}}, nil
		}
	case "prompts.get":
		return allow, nil
	case "resources.read", "resources.subscribe":
		if strings.HasPrefix(in.Resource.Name, "file:///ok/") {
			return allow, nil
		}
	case "completion.complete":
		return allow, nil
	case "roots.list":
		return allow, nil
	case "sampling.create":
		if in.Resource.Server == "moderndeny" {
			return deny, nil
		}
		return pep.Decision{Effect: pep.Allow, Obligations: &pep.Obligations{Pseudonymize: &pseudo.Spec{Detect: []string{"email"}}}}, nil
	case "elicitation.create":
		if in.Args["sensitive"] == true || in.Resource.Server == "moderndeny" {
			return deny, nil
		}
		return allow, nil
	}
	return deny, nil
}

func (f fakePDP) Visible(ctx context.Context, p principal.Principal, rs []pep.Resource) ([]pep.Resource, error) {
	actions := map[string]string{"tool": "tools.call", "prompt": "prompts.get", "resource": "resources.read", "resource_template": "completion.complete"}
	var out []pep.Resource
	for _, r := range rs {
		if d, _ := f.Decide(ctx, pep.Input{Principal: p, Action: actions[r.Kind], Resource: r}); d.Effect != pep.Deny {
			out = append(out, r)
		}
	}
	return out, nil
}

// testObligations are attached to allows of these tools.
var testObligations = map[string]pep.Obligations{
	"read_secret":     {RedactOutput: []string{`token=\S+`}},
	"read_big":        {MaxOutputBytes: 64},
	"read_limited":    {RateLimit: pep.StringList{"2/m"}},
	"read_path":       {ArgConstraints: map[string]pep.StringList{"path": {"^/ok/"}}},
	"read_audited":    {Audit: "full"},
	"read_broken":     {RedactOutput: []string{"("}},
	"read_customer":   {Pseudonymize: customerSpec},
	"update_customer": {Pseudonymize: customerSpec, Reidentify: pep.StringList{"id", "note"}},
}

var customerSpec = &pseudo.Spec{Detect: []string{"email"}, Fields: map[string]string{"name": "person", "id": "customer"}}

// fakeLauncher starts in-process fake backends and records them.
type fakeLauncher struct {
	t  *testing.T
	mu sync.Mutex
	// instances by backend name, in start order
	instances map[string][]*fakeInstance
	// fail, if set, is returned by Start.
	fail error
	// failFor, if set, may refuse starts for some principals.
	failFor func(principal.Principal) error
}

func newFakeLauncher(t *testing.T) *fakeLauncher {
	return &fakeLauncher{t: t, instances: map[string][]*fakeInstance{}}
}

func (l *fakeLauncher) Start(_ context.Context, b *config.Backend, p principal.Principal, id string) (supervisor.Instance, error) {
	l.mu.Lock()
	err := l.fail
	if err == nil && l.failFor != nil {
		err = l.failFor(p)
	}
	l.mu.Unlock()
	if err != nil {
		return nil, err
	}
	gw, be := net.Pipe()
	fi := &fakeInstance{Conn: gw, name: b.Name, id: id, p: p, closed: make(chan struct{}), cancelled: make(chan string, 10), commit: make(chan struct{})}
	fi.be = jsonrpc.NewConn(be)
	go fi.serve(fi.be)
	l.mu.Lock()
	l.instances[b.Name] = append(l.instances[b.Name], fi)
	l.mu.Unlock()
	return fi, nil
}

func (l *fakeLauncher) started(name string) []*fakeInstance {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]*fakeInstance(nil), l.instances[name]...)
}

type fakeInstance struct {
	net.Conn
	name      string
	id        string
	p         principal.Principal // whom the instance runs for
	be        *jsonrpc.Conn       // the backend's end
	lists     atomic.Int32        // tools/list listings served
	closeOnce sync.Once
	closed    chan struct{}
	cancelled chan string // request ids the backend was told to cancel
	// commit, once closed, lets "commit" calls finish; they ignore
	// cancellation (like an RPM transaction).
	commit chan struct{}

	argsMu   sync.Mutex
	lastArgs json.RawMessage // arguments of the last update_customer call

	// Requests the backend received (methods, and the _meta of each),
	// and for "modern…" backends the filters of subscriptions/listen.
	seenMu  sync.Mutex
	methods []string
	metas   []map[string]json.RawMessage
	listens []json.RawMessage
}

func (f *fakeInstance) seen() ([]string, []map[string]json.RawMessage, []json.RawMessage) {
	f.seenMu.Lock()
	defer f.seenMu.Unlock()
	return append([]string(nil), f.methods...), append([]map[string]json.RawMessage(nil), f.metas...), append([]json.RawMessage(nil), f.listens...)
}

func (f *fakeInstance) updateArgs() string {
	f.argsMu.Lock()
	defer f.argsMu.Unlock()
	return string(f.lastArgs)
}

func (f *fakeInstance) Name() string { return "fake-" + f.name + "-" + f.id }

// notify sends a notification from the backend.
func (f *fakeInstance) notify(method string) {
	n, _ := jsonrpc.NewNotification(method, nil)
	_ = f.be.Write(n)
}

func (f *fakeInstance) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return f.Conn.Close()
}

func result(t *testing.T, id json.RawMessage, v any) *jsonrpc.Message {
	m, err := jsonrpc.NewResult(id, v)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func text(s string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": s}}}
}

// serve implements a small MCP server named after the backend.
func (f *fakeInstance) serve(c *jsonrpc.Conn) {
	var (
		mu      sync.Mutex
		nextID  int
		waiting = map[string]chan *jsonrpc.Message{}
	)
	// ask sends a request to the gateway (as the backend's client).
	ask := func(method string, params any) *jsonrpc.Message {
		mu.Lock()
		nextID++
		id := json.RawMessage(`"be-` + string(rune('0'+nextID)) + `"`)
		ch := make(chan *jsonrpc.Message, 1)
		waiting[string(id)] = ch
		mu.Unlock()
		req, _ := jsonrpc.NewRequest(id, method, params)
		_ = c.Write(req)
		return <-ch
	}
	respond := func(m *jsonrpc.Message, v any) {
		r, _ := jsonrpc.NewResult(m.ID, v)
		_ = c.Write(r)
	}
	slow := map[string]chan struct{}{}
	for {
		m, err := c.Read()
		if err != nil {
			return
		}
		if m.IsResponse() {
			mu.Lock()
			ch := waiting[m.Key()]
			mu.Unlock()
			if ch != nil {
				ch <- m
			}
			continue
		}
		if m.IsNotification() {
			if m.Method == "notifications/cancelled" {
				var p struct {
					RequestID json.RawMessage `json:"requestId"`
				}
				_ = json.Unmarshal(m.Params, &p)
				mu.Lock()
				if ch := slow[string(p.RequestID)]; ch != nil {
					close(ch)
				}
				mu.Unlock()
				f.cancelled <- string(p.RequestID)
			}
			continue
		}
		var p struct {
			Name   string          `json:"name"`
			URI    string          `json:"uri"`
			Cursor string          `json:"cursor"`
			Args   json.RawMessage `json:"arguments"`
			Meta   json.RawMessage `json:"_meta"`
		}
		_ = json.Unmarshal(m.Params, &p)
		var meta map[string]json.RawMessage
		_ = json.Unmarshal(p.Meta, &meta)
		f.seenMu.Lock()
		f.methods = append(f.methods, m.Method)
		f.metas = append(f.metas, meta)
		f.seenMu.Unlock()
		if f.modernRequest(c, m, p.Name, meta) {
			continue
		}
		switch m.Method {
		case "initialize":
			caps := map[string]any{"tools": map[string]any{}, "prompts": map[string]any{}, "resources": map[string]any{}}
			if strings.HasPrefix(f.name, "toolsonly") {
				caps = map[string]any{"tools": map[string]any{}}
			}
			respond(m, map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    caps,
				"serverInfo":      map[string]any{"name": "fake-" + f.name},
			})
		case "tools/list":
			if p.Cursor == "" {
				f.lists.Add(1) // listings, not pages
			}
			// Two pages.
			if p.Cursor == "" {
				respond(m, map[string]any{"tools": []map[string]any{
					{"name": "read_file", "inputSchema": map[string]any{"type": "object",
						"properties": map[string]any{"path": map[string]any{"type": "string"}, "mode": map[string]any{"type": "string"}}}},
					{"name": "write_file", "inputSchema": map[string]any{"type": "object"}},
				}, "nextCursor": "p2"})
			} else {
				tools := []map[string]any{
					{"name": "delete_file", "inputSchema": map[string]any{"type": "object"}},
					{"name": "ask_roots", "inputSchema": map[string]any{"type": "object"}},
				}
				if strings.HasPrefix(f.name, "regional") {
					// A parameter mirrored into a header (MCP 2026-07-28).
					tools = append(tools, map[string]any{"name": "read_region", "inputSchema": map[string]any{"type": "object",
						"properties": map[string]any{"region": map[string]any{"type": "string", "x-mcp-header": "Region"}}}})
				}
				respond(m, map[string]any{"tools": tools})
			}
		case "tools/call":
			switch p.Name {
			case "ask_roots":
				go func(m *jsonrpc.Message) {
					resp := ask("roots/list", map[string]any{})
					if resp.Error != nil {
						respond(m, text("roots error: "+resp.Error.Message))
						return
					}
					respond(m, text("roots: "+string(resp.Result)))
				}(m)
			case "commit":
				go func(m *jsonrpc.Message) {
					<-f.commit
					respond(m, text("committed"))
				}(m)
			case "slow":
				ch := make(chan struct{})
				mu.Lock()
				slow[m.Key()] = ch
				mu.Unlock()
			case "ask_color", "ask_secret":
				field := map[string]any{"color": map[string]any{"type": "string"}}
				if p.Name == "ask_secret" {
					field = map[string]any{"password": map[string]any{"type": "string"}}
				}
				go func(m *jsonrpc.Message) {
					resp := ask("elicitation/create", map[string]any{"message": "Question",
						"requestedSchema": map[string]any{"type": "object", "properties": field}})
					if resp.Error != nil {
						respond(m, text("elicitation error: "+resp.Error.Message))
						return
					}
					respond(m, text("answer: "+string(resp.Result)))
				}(m)
			case "read_renewed_token":
				// As mcp-http-connector after a 401 (mcp-gateway/token).
				go func(m *jsonrpc.Message) {
					resp := ask("mcp-gateway/token", map[string]any{"refused": "old"})
					if resp.Error != nil {
						respond(m, text("token error: "+resp.Error.Message))
						return
					}
					respond(m, text("token: "+string(resp.Result)))
				}(m)
			case "read_customer":
				respond(m, text(`{"id":4711,"name":"Alice Doe","email":"alice@example.com","manager":"forbidden@example.com"}`))
			case "update_customer":
				f.argsMu.Lock()
				f.lastArgs = p.Args
				f.argsMu.Unlock()
				respond(m, text("updated"))
			case "ask_llm":
				go func(m *jsonrpc.Message) {
					resp := ask("sampling/createMessage", map[string]any{"maxTokens": 100, "messages": []map[string]any{
						{"role": "user", "content": map[string]any{"type": "text", "text": "Summarize the mail from carol@example.com"}}}})
					if resp.Error != nil {
						respond(m, text("sampling error: "+resp.Error.Message))
						return
					}
					respond(m, text("llm: "+string(resp.Result)))
				}(m)
			case "read_secret":
				respond(m, text("user=bob token=abc123 done"))
			case "read_task":
				var raw map[string]json.RawMessage
				_ = json.Unmarshal(m.Params, &raw)
				if _, ok := raw["task"]; ok {
					respond(m, text("task requested"))
				} else {
					respond(m, text("no task"))
				}
			case "read_big":
				respond(m, text(strings.Repeat("x", 200)))
			case "progress", "write_progress":
				var meta struct {
					ProgressToken json.RawMessage `json:"progressToken"`
				}
				_ = json.Unmarshal(p.Meta, &meta)
				n, _ := jsonrpc.NewNotification("notifications/progress", map[string]any{"progressToken": meta.ProgressToken, "progress": 1, "total": 2})
				_ = c.Write(n)
				respond(m, text("done"))
			default:
				respond(m, text(f.name+" did "+p.Name))
			}
		case "prompts/list":
			respond(m, map[string]any{"prompts": []map[string]any{{"name": "summarize"}}})
		case "prompts/get":
			respond(m, map[string]any{"messages": []map[string]any{{"role": "user", "content": map[string]any{"type": "text", "text": f.name + " prompt " + p.Name}}}})
		case "resources/list":
			respond(m, map[string]any{"resources": []map[string]any{
				{"uri": "file:///ok/a.txt", "name": "a"},
				{"uri": "file:///secret", "name": "secret"},
			}})
		case "resources/templates/list":
			respond(m, map[string]any{"resourceTemplates": []map[string]any{{"uriTemplate": "file:///ok/{name}", "name": "ok"}}})
		case "resources/read":
			if strings.HasSuffix(p.URI, "/missing") {
				_ = c.Write(jsonrpc.NewError(m.ID, -32002, "resource not found"))
				break
			}
			respond(m, map[string]any{"contents": []map[string]any{{"uri": p.URI, "text": f.name + " content"}}})
		case "resources/subscribe":
			respond(m, map[string]any{})
			// An update of the subscribed resource, and one of a resource
			// policy does not allow (as after a revocation).
			for _, uri := range []string{p.URI, "file:///secret"} {
				n, _ := jsonrpc.NewNotification("notifications/resources/updated", map[string]any{"uri": uri})
				_ = c.Write(n)
			}
		case "completion/complete":
			respond(m, map[string]any{"completion": map[string]any{"values": []string{f.name}}})
		default:
			_ = c.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeMethodNotFound, "nope"))
		}
	}
}

// modernRequest serves what differs for backends named "modern…" (MCP
// 2026-07-28: server/discover, no initialize, subscriptions/listen) and
// "fragile…" (a legacy server that ends on a request before initialize,
// the first time), "silent…" (never answers server/discover), "refused…"
// and "unavailable…" (failing as the connector reports a refused token
// or an HTTP 503); it reports whether it answered m.
func (f *fakeInstance) modernRequest(c *jsonrpc.Conn, m *jsonrpc.Message, name string, meta map[string]json.RawMessage) bool {
	if strings.HasPrefix(f.name, "fragile") && m.Method == "server/discover" {
		_ = f.Close()
		return true
	}
	if strings.HasPrefix(f.name, "silent") && m.Method == "server/discover" {
		return true // never answers
	}
	if m.Method == "server/discover" || m.Method == "initialize" {
		// What the connector answers when the HTTP server refuses the
		// token, or is not available.
		switch {
		case strings.HasPrefix(f.name, "refused"):
			_ = c.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeInternalError, "MCP server over HTTP: the server refused the access token (HTTP 401)"))
			return true
		case strings.HasPrefix(f.name, "unavailable"):
			_ = c.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeInternalError, "MCP server over HTTP: HTTP 503 Service Unavailable: busy"))
			return true
		}
	}
	if !strings.HasPrefix(f.name, "modern") {
		return false
	}
	if string(meta[metaProtocolVersion]) != `"`+modernVersion+`"` || meta[metaClientCapabilities] == nil {
		_ = c.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeInvalidParams, "missing per-request metadata"))
		return true
	}
	respond := func(v map[string]any) {
		if v["resultType"] == nil {
			v["resultType"] = "complete"
		}
		r, _ := jsonrpc.NewResult(m.ID, v)
		_ = c.Write(r)
	}
	switch m.Method {
	case "server/discover":
		if strings.HasPrefix(f.name, "modernnext") {
			e := jsonrpc.NewError(m.ID, codeUnsupportedVersion, "Unsupported protocol version")
			e.Error.Data = json.RawMessage(`{"supported":["2027-03-01"],"requested":"` + modernVersion + `"}`)
			_ = c.Write(e)
			return true
		}
		respond(map[string]any{
			"supportedVersions": []string{modernVersion},
			"capabilities":      map[string]any{"tools": map[string]any{"listChanged": true}, "resources": map[string]any{}, "logging": map[string]any{}},
			"instructions":      "modern instructions",
			"_meta":             map[string]any{metaServerInfo: map[string]any{"name": "fake-" + f.name}},
		})
	case "initialize", "resources/subscribe", "resources/unsubscribe", "logging/setLevel", "ping":
		_ = c.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeMethodNotFound, "not in MCP "+modernVersion))
	case "subscriptions/listen":
		var p struct {
			Notifications json.RawMessage `json:"notifications"`
		}
		_ = json.Unmarshal(m.Params, &p)
		f.seenMu.Lock()
		f.listens = append(f.listens, p.Notifications)
		f.seenMu.Unlock()
		ack, _ := jsonrpc.NewNotification("notifications/subscriptions/acknowledged", map[string]any{
			"_meta": map[string]any{metaSubscriptionID: m.ID}, "notifications": p.Notifications})
		_ = c.Write(ack)
	case "tools/call":
		switch name {
		case "ask_input", "ask_secret", "ask_sample", "ask_forever":
			// Input asked for with a result (multi round-trip): the
			// answers and the state come back with the next call.
			var in struct {
				InputResponses json.RawMessage `json:"inputResponses"`
				RequestState   *string         `json:"requestState"`
			}
			_ = json.Unmarshal(m.Params, &in)
			if in.RequestState != nil && *in.RequestState == "s1" && name != "ask_forever" {
				respond(text("answers " + string(in.InputResponses)))
				return true
			}
			requests := map[string]any{
				"ask_input": map[string]any{
					"name": map[string]any{"method": "elicitation/create", "params": map[string]any{"message": "Your name?",
						"requestedSchema": map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string"}}}}},
					"roots": map[string]any{"method": "roots/list", "params": map[string]any{}},
				},
				"ask_secret": map[string]any{
					"pw": map[string]any{"method": "elicitation/create", "params": map[string]any{"message": "Password?",
						"requestedSchema": map[string]any{"type": "object", "properties": map[string]any{"password": map[string]any{"type": "string"}}}}},
				},
				"ask_sample": map[string]any{
					"llm": map[string]any{"method": "sampling/createMessage", "params": map[string]any{"maxTokens": 10,
						"messages": []any{map[string]any{"role": "user", "content": map[string]any{"type": "text", "text": "hi"}}}}},
				},
			}[name]
			r := map[string]any{"resultType": "input_required", "requestState": "s1"}
			if requests != nil {
				r["inputRequests"] = requests
			}
			respond(r)
		case "read_log":
			if meta[metaLogLevel] != nil {
				n, _ := jsonrpc.NewNotification("notifications/message", map[string]any{"level": "info", "data": "logged"})
				_ = c.Write(n)
			}
			respond(text("log level " + string(meta[metaLogLevel])))
		default:
			respond(text(f.name + " did " + name))
		}
	default:
		return false
	}
	return true
}
