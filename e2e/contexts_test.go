package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// modern is the _meta of a request of an agent of MCP 2026-07-28.
func modern(params map[string]any) map[string]any {
	out := map[string]any{"_meta": map[string]any{
		"io.modelcontextprotocol/protocolVersion":    "2026-07-28",
		"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "e2e-modern", "version": "1"},
		"io.modelcontextprotocol/clientCapabilities": map[string]any{},
	}}
	for k, v := range params {
		out[k] = v
	}
	return out
}

// Contexts (D22) with the shipped policy: a modern agent opens two
// contexts of a server with contexts: true, each call in one runs in an
// instance of its own (listed with its context in the control API),
// ending one stops its instance and the id is refused after. A server
// whose role denies every tool offers no contexts.
func TestContexts(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	home, err := os.MkdirTemp("", "mcpgw-ctx")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	writeFile(t, filepath.Join(home, "notes.txt"), "context notes")
	rbac := fmt.Sprintf(`{
	  "roles": {"browsing": {"permissions": [
	    {"server": "fs", "tool": "read_*"},
	    {"server": "fs", "tool": "list_*"},
	    {"server": "fs", "tool": "delete_*", "effect": "deny"},
	    {"server": "locked", "tool": "list_allowed_directories"},
	    {"server": "locked", "tool": "*", "effect": "deny"}
	  ]}},
	  "bindings": {"groups": {}, "users": {%q: ["browsing"]}}
	}`, me.Username)
	e := setup(t, rbac, nil, "")
	demo := filepath.Join(e.tmp, "bin", "mcp-server-fs")
	for _, name := range []string{"fs", "locked"} {
		writeFile(t, filepath.Join(e.tmp, "servers.d", name+".yaml"), fmt.Sprintf(
			"name: %s\ncommand: [%q, --root, %q]\nrun_as: gateway\nisolation: session\ncontexts: true\n", name, demo, home))
	}
	defer func() {
		if t.Failed() {
			t.Logf("gateway:\n%s", e.gwLogs.String())
		}
	}()
	c := newClient(t, e.connect, e.gwSock, "fs")
	id := 1
	request := func(method string, params map[string]any) msg {
		t.Helper()
		id++
		c.request(id, method, modern(params))
		return c.read()
	}
	call := func(tool string, args map[string]any) msg {
		t.Helper()
		return request("tools/call", map[string]any{"name": tool, "arguments": args})
	}

	// The definitions are loaded while the gateway runs.
	deadline := time.Now().Add(15 * time.Second)
	for {
		m := request("tools/list", nil)
		if m.Error == nil && strings.Contains(listNames(t, m, "tools", "name"), "gateway_new_context") {
			if !strings.Contains(string(m.Result), `"gateway_context"`) {
				t.Fatalf("no gateway_context on the tools: %s", m.Result)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no context tools: %+v %s", m.Error, m.Result)
		}
		time.Sleep(200 * time.Millisecond)
	}

	open := func() string {
		t.Helper()
		m := call("gateway_new_context", map[string]any{})
		var res struct {
			Structured struct{ Context string } `json:"structuredContent"`
		}
		if m.Error != nil || json.Unmarshal(m.Result, &res) != nil || !strings.HasPrefix(res.Structured.Context, "ctx_") {
			t.Fatalf("gateway_new_context: %+v %s", m.Error, m.Result)
		}
		return res.Structured.Context
	}
	a, b := open(), open()
	read := filepath.Join(home, "notes.txt")
	for _, ctx := range []string{a, b, ""} {
		args := map[string]any{"path": read}
		if ctx != "" {
			args["gateway_context"] = ctx
		}
		if text, isErr := toolResult(t, call("read_text_file", args)); isErr || !strings.Contains(text, "context notes") {
			t.Fatalf("read in %q: %q", ctx, text)
		}
	}

	ctl := controlClient(e.ctlSock)
	instances := func() (contexts []string, isolation map[string]string) {
		t.Helper()
		var servers []struct {
			Name      string
			Instances []struct {
				ID, Context, Isolation string
			}
		}
		controlDo(t, ctl, "GET", "/v1/servers", "", &servers)
		isolation = map[string]string{}
		for _, s := range servers {
			if s.Name != "fs" {
				continue
			}
			for _, in := range s.Instances {
				contexts = append(contexts, in.Context)
				isolation[in.Context] = in.Isolation
			}
		}
		slices.Sort(contexts)
		return contexts, isolation
	}
	want := []string{"", a, b}
	slices.Sort(want)
	got, iso := instances()
	if !slices.Equal(got, want) || iso[a] != "context" || iso[""] != "principal" {
		t.Fatalf("instances by context %q (%v), want %q", got, iso, want)
	}

	if text, isErr := toolResult(t, call("gateway_end_context", map[string]any{"gateway_context": a})); isErr || !strings.Contains(text, a) {
		t.Fatalf("end: %q", text)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		got, _ = instances()
		if !slices.Contains(got, a) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the ended context's instance runs on: %q", got)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if m := call("read_text_file", map[string]any{"path": read, "gateway_context": a}); m.Error == nil || !strings.Contains(m.Error.Message, "gateway_new_context") {
		t.Fatalf("an ended context: %+v %s", m.Error, m.Result)
	}
	if text, isErr := toolResult(t, call("read_text_file", map[string]any{"path": read, "gateway_context": b})); isErr {
		t.Fatalf("the other context: %q", text)
	}
	if !strings.Contains(e.gwLogs.String(), "context opened") {
		t.Errorf("not logged")
	}

	// A role that denies every tool of the server offers no contexts.
	lc := newClient(t, e.connect, e.gwSock, "locked")
	lc.request(1, "tools/list", modern(nil))
	if m := lc.read(); m.Error != nil || strings.Contains(listNames(t, m, "tools", "name"), "gateway_new_context") {
		t.Fatalf("locked: %+v %s", m.Error, m.Result)
	}
	lc.request(2, "tools/call", modern(map[string]any{"name": "gateway_new_context", "arguments": map[string]any{}}))
	if m := lc.read(); m.Error == nil && !strings.Contains(string(m.Result), `"isError":true`) {
		t.Fatalf("locked: a context opened: %s", m.Result)
	}
}
