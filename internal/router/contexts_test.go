package router

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// contextRouter is testRouter with "browser", a server with contexts.
func contextRouter(t *testing.T) (*Router, *fakeLauncher) {
	t.Helper()
	r, l := testRouter(t, time.Hour)
	r.Backends["browser"] = &config.Backend{Name: "browser", Isolation: config.IsolationSession, Contexts: true}
	return r, l
}

// openContext calls gateway_new_context (named as on the endpoint) and
// returns the context's id.
func openContext(t *testing.T, c *client, id int, tool string) string {
	t.Helper()
	m := c.roundTrip(id, "tools/call", withAgentMeta(map[string]any{"name": tool}, nil))
	var res struct {
		Structured struct {
			Context string `json:"context"`
		} `json:"structuredContent"`
	}
	if m.Error != nil || json.Unmarshal(m.Result, &res) != nil || !strings.HasPrefix(res.Structured.Context, "ctx_") {
		t.Fatalf("%s: %+v %s", tool, m.Error, m.Result)
	}
	return res.Structured.Context
}

// counted calls read_counter, in context ctx if not "", and returns its
// text.
func counted(t *testing.T, c *client, id int, tool, ctx string) string {
	t.Helper()
	args := map[string]any{}
	if ctx != "" {
		args[contextArg] = ctx
	}
	text, isErr := toolText(t, c.roundTrip(id, "tools/call", withAgentMeta(map[string]any{"name": tool, "arguments": args}, nil)))
	if isErr {
		t.Fatalf("read_counter in %q: %s", ctx, text)
	}
	return text
}

// A modern agent sees the context tools of a server with contexts, and
// the argument gateway_context on its tools; a legacy session (its own
// instance already) and a server without contexts do not.
func TestContextsListed(t *testing.T) {
	r, _ := contextRouter(t)
	m := agent(t, r, alice(), "browser").roundTrip(1, "tools/list", withAgentMeta(nil, nil))
	got := names(t, m, "tools", "name")
	if !slices.Contains(got, newContextTool) || !slices.Contains(got, endContextTool) {
		t.Fatalf("tools %v", got)
	}
	var res struct {
		Tools []struct {
			Name        string `json:"name"`
			InputSchema struct {
				Properties map[string]json.RawMessage `json:"properties"`
				Required   []string                   `json:"required"`
			} `json:"inputSchema"`
		} `json:"tools"`
	}
	_ = json.Unmarshal(m.Result, &res)
	for _, tool := range res.Tools {
		_, has := tool.InputSchema.Properties[contextArg]
		switch tool.Name {
		case newContextTool:
			if has {
				t.Errorf("%s takes a context", tool.Name)
			}
		case endContextTool:
			if !has || !slices.Equal(tool.InputSchema.Required, []string{contextArg}) {
				t.Errorf("%s: %+v", tool.Name, tool.InputSchema)
			}
		default:
			if !has || slices.Contains(tool.InputSchema.Required, contextArg) {
				t.Errorf("%s: no optional %s: %+v", tool.Name, contextArg, tool.InputSchema)
			}
		}
	}
	// read_file keeps its own properties.
	for _, tool := range res.Tools {
		if _, ok := tool.InputSchema.Properties["path"]; tool.Name == "read_file" && !ok {
			t.Errorf("read_file lost path: %+v", tool.InputSchema)
		}
	}

	legacy := connect(t, r, alice(), "browser", nil).roundTrip(1, "tools/list", nil)
	if got := names(t, legacy, "tools", "name"); slices.Contains(got, newContextTool) || strings.Contains(string(legacy.Result), contextArg) {
		t.Errorf("legacy session: %v", got)
	}
	tmp := agent(t, r, alice(), "tmp").roundTrip(1, "tools/list", withAgentMeta(nil, nil))
	if got := names(t, tmp, "tools", "name"); slices.Contains(got, newContextTool) || strings.Contains(string(tmp.Result), contextArg) {
		t.Errorf("server without contexts: %v", got)
	}
	// Policy decides on the context tools: hidden from "nobody".
	nobody := principal.Principal{Sub: "nobody", Transport: principal.TransportUnix, Home: "/home/nobody"}
	if got := names(t, agent(t, r, nobody, "browser").roundTrip(1, "tools/list", withAgentMeta(nil, nil)), "tools", "name"); slices.Contains(got, newContextTool) {
		t.Errorf("nobody: %v", got)
	}
}

// Each context has an instance of its own, with its own state; calls
// without a context share the principal's; the argument does not reach
// the server. An ended context's instance stops, and the id is refused.
func TestContextsInstances(t *testing.T) {
	r, l := contextRouter(t)
	c := agent(t, r, alice(), "browser")
	a := openContext(t, c, 1, newContextTool)
	b := openContext(t, c, 2, newContextTool)
	if a == b {
		t.Fatal("the same id twice")
	}
	steps := []struct{ ctx, want string }{
		{"", "browser count 1"}, {a, "browser count 1"}, {a, "browser count 2"},
		{"", "browser count 2"}, {b, "browser count 1"}, {a, "browser count 3"},
	}
	for i, st := range steps {
		if got := counted(t, c, 10+i, "read_counter", st.ctx); got != st.want {
			t.Errorf("step %d in %q: %q, want %q", i, st.ctx, got, st.want)
		}
	}
	started := l.started("browser")
	var contexts []string
	for _, fi := range started {
		contexts = append(contexts, fi.p.Context)
		fi.seenMu.Lock()
		for _, args := range fi.callArgs {
			if strings.Contains(string(args), contextArg) {
				t.Errorf("the server got %s: %s", contextArg, args)
			}
		}
		fi.seenMu.Unlock()
	}
	slices.Sort(contexts)
	want := []string{"", a, b}
	slices.Sort(want)
	if !slices.Equal(contexts, want) {
		t.Fatalf("instances for contexts %q, want %q", contexts, want)
	}
	var infos []InstanceInfo
	for _, info := range r.Instances() {
		if info.Server == "browser" && info.Context != "" {
			infos = append(infos, info)
		}
	}
	if len(infos) != 2 || infos[0].Isolation != config.IsolationContext {
		t.Errorf("instances listed: %+v", infos)
	}

	m := c.roundTrip(30, "tools/call", withAgentMeta(map[string]any{"name": endContextTool, "arguments": map[string]any{contextArg: a}}, nil))
	if text, isErr := toolText(t, m); isErr || !strings.Contains(text, "Ended context "+a) {
		t.Fatalf("end: %q", text)
	}
	var instA *fakeInstance
	for _, fi := range started {
		if fi.p.Context == a {
			instA = fi
		}
	}
	select {
	case <-instA.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the ended context's instance runs on")
	}
	m = c.roundTrip(31, "tools/call", withAgentMeta(map[string]any{"name": "read_counter", "arguments": map[string]any{contextArg: a}}, nil))
	if m.Error == nil || m.Error.Code != jsonrpc.CodeInvalidParams || !strings.Contains(m.Error.Message, newContextTool) {
		t.Fatalf("an ended context: %+v", m)
	}
	m = c.roundTrip(32, "tools/call", withAgentMeta(map[string]any{"name": endContextTool, "arguments": map[string]any{contextArg: a}}, nil))
	if m.Error == nil || m.Error.Code != jsonrpc.CodeInvalidParams {
		t.Fatalf("ending it again: %+v", m)
	}
	if got := counted(t, c, 33, "read_counter", b); got != "browser count 2" {
		t.Errorf("the other context: %q", got)
	}
	m = c.roundTrip(34, "tools/call", withAgentMeta(map[string]any{"name": "read_counter", "arguments": map[string]any{contextArg: 7}}, nil))
	if m.Error == nil || !strings.Contains(m.Error.Message, "must be a string") {
		t.Errorf("a context that is no string: %+v", m)
	}
}

// A context is its principal's and its server's: another principal, or
// a call of another server, cannot use or end it.
func TestContextsOwned(t *testing.T) {
	r, _ := contextRouter(t)
	r.Backends["notes"] = &config.Backend{Name: "notes", Isolation: config.IsolationSession, Contexts: true}
	c := agent(t, r, alice(), "")
	id := openContext(t, c, 1, "browser"+nameSep+newContextTool)
	if got := counted(t, c, 2, "browser"+nameSep+"read_counter", id); got != "browser count 1" {
		t.Fatalf("aggregated: %q", got)
	}
	m := c.roundTrip(3, "tools/call", withAgentMeta(map[string]any{"name": "notes" + nameSep + "read_counter", "arguments": map[string]any{contextArg: id}}, nil))
	if m.Error == nil || m.Error.Code != jsonrpc.CodeInvalidParams {
		t.Errorf("another server: %+v", m)
	}
	uid := uint32(1002)
	bob := principal.Principal{Sub: "bob", UID: &uid, Home: "/home/bob", Transport: principal.TransportUnix}
	cb := agent(t, r, bob, "browser")
	m = cb.roundTrip(1, "tools/call", withAgentMeta(map[string]any{"name": "read_counter", "arguments": map[string]any{contextArg: id}}, nil))
	if m.Error == nil || m.Error.Code != jsonrpc.CodeInvalidParams {
		t.Errorf("bob uses alice's context: %+v", m)
	}
	m = cb.roundTrip(2, "tools/call", withAgentMeta(map[string]any{"name": endContextTool, "arguments": map[string]any{contextArg: id}}, nil))
	if m.Error == nil {
		t.Errorf("bob ends alice's context: %+v", m)
	}
	if got := counted(t, c, 4, "browser"+nameSep+"read_counter", id); got != "browser count 2" {
		t.Errorf("alice's context after bob: %q", got)
	}
}

// limits.contexts_per_principal: more are refused, naming the tool that
// ends one.
func TestContextsLimit(t *testing.T) {
	r, _ := contextRouter(t)
	r.MaxContextsPerPrincipal = 2
	c := agent(t, r, alice(), "browser")
	openContext(t, c, 1, newContextTool)
	openContext(t, c, 2, newContextTool)
	m := c.roundTrip(3, "tools/call", withAgentMeta(map[string]any{"name": newContextTool}, nil))
	if m.Error == nil || !strings.Contains(m.Error.Message, "contexts_per_principal") || !strings.Contains(m.Error.Message, endContextTool) {
		t.Fatalf("a third: %+v", m)
	}
}

// A context ends after the idle timeout without a call; a call keeps it.
func TestContextStoreExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	c := &contextStore{now: func() time.Time { return now }}
	p := principal.Principal{Sub: "alice", Transport: principal.TransportUnix}
	id, err := c.open(p, "browser", 8, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(50 * time.Second)
	if !c.use(p, "browser", id, time.Minute) {
		t.Fatal("refused in time")
	}
	now = now.Add(50 * time.Second)
	if !c.use(p, "browser", id, time.Minute) {
		t.Fatal("a call did not keep it")
	}
	now = now.Add(61 * time.Second)
	if c.use(p, "browser", id, time.Minute) {
		t.Fatal("used after the idle timeout")
	}
	if ids := c.list(p, "browser", time.Minute); len(ids) != 0 {
		t.Errorf("listed after it: %v", ids)
	}
}

// An idle context's instance does not make room for another instance:
// it holds the agent's state.
func TestContextInstanceNotEvicted(t *testing.T) {
	r, _ := contextRouter(t)
	r.MaxInstancesPerPrincipal = 2
	c := agent(t, r, alice(), "browser")
	id := openContext(t, c, 1, newContextTool)
	counted(t, c, 2, "read_counter", id)
	counted(t, c, 3, "read_counter", "")
	// Two instances, both idle: a third server's instance must evict the
	// principal's, not the context's.
	if text, isErr := toolText(t, agent(t, r, alice(), "fs").roundTrip(1, "tools/call", withAgentMeta(map[string]any{"name": "read_file"}, nil))); isErr {
		t.Fatalf("fs: %s", text)
	}
	if got := counted(t, c, 4, "read_counter", id); got != "browser count 2" {
		t.Errorf("the context's instance was evicted: %q", got)
	}
}
