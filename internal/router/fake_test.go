package router

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
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
		if o, ok := testObligations[in.Resource.Name]; ok {
			return pep.Decision{Effect: pep.Allow, Obligations: &o}, nil
		}
		switch {
		case strings.HasPrefix(in.Resource.Name, "read_"), strings.HasPrefix(in.Resource.Name, "ask_"),
			in.Resource.Name == "slow", in.Resource.Name == "progress":
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
	case "elicitation.create":
		if in.Args["sensitive"] == true {
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
	"read_secret":  {RedactOutput: []string{`token=\S+`}},
	"read_big":     {MaxOutputBytes: 64},
	"read_limited": {RateLimit: pep.StringList{"2/m"}},
	"read_path":    {ArgConstraints: map[string]pep.StringList{"path": {"^/ok/"}}},
	"read_audited": {Audit: "full"},
	"read_broken":  {RedactOutput: []string{"("}},
}

// fakeLauncher starts in-process fake backends and records them.
type fakeLauncher struct {
	t  *testing.T
	mu sync.Mutex
	// instances by backend name, in start order
	instances map[string][]*fakeInstance
}

func newFakeLauncher(t *testing.T) *fakeLauncher {
	return &fakeLauncher{t: t, instances: map[string][]*fakeInstance{}}
}

func (l *fakeLauncher) Start(_ context.Context, b *config.Backend, _ principal.Principal, id string) (supervisor.Instance, error) {
	gw, be := net.Pipe()
	fi := &fakeInstance{Conn: gw, name: b.Name, id: id, closed: make(chan struct{}), cancelled: make(chan string, 10)}
	go fi.serve(jsonrpc.NewConn(be))
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
	closeOnce sync.Once
	closed    chan struct{}
	cancelled chan string // request ids the backend was told to cancel
}

func (f *fakeInstance) Name() string { return "fake-" + f.name + "-" + f.id }

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
			Meta   json.RawMessage `json:"_meta"`
		}
		_ = json.Unmarshal(m.Params, &p)
		switch m.Method {
		case "initialize":
			respond(m, map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{"tools": map[string]any{}, "prompts": map[string]any{}, "resources": map[string]any{}},
				"serverInfo":      map[string]any{"name": "fake-" + f.name},
			})
		case "tools/list":
			// Two pages.
			if p.Cursor == "" {
				respond(m, map[string]any{"tools": []map[string]any{
					{"name": "read_file", "inputSchema": map[string]any{"type": "object"}},
					{"name": "write_file", "inputSchema": map[string]any{"type": "object"}},
				}, "nextCursor": "p2"})
			} else {
				respond(m, map[string]any{"tools": []map[string]any{
					{"name": "delete_file", "inputSchema": map[string]any{"type": "object"}},
					{"name": "ask_roots", "inputSchema": map[string]any{"type": "object"}},
				}})
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
			case "read_secret":
				respond(m, text("user=bob token=abc123 done"))
			case "read_big":
				respond(m, text(strings.Repeat("x", 200)))
			case "progress":
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
			respond(m, map[string]any{"contents": []map[string]any{{"uri": p.URI, "text": f.name + " content"}}})
		case "completion/complete":
			respond(m, map[string]any{"completion": map[string]any{"values": []string{f.name}}})
		default:
			_ = c.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeMethodNotFound, "nope"))
		}
	}
}
