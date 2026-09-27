// Package e2e runs the gateway end to end: a real OPA server with the
// shipped policy, the gateway (exec supervisor), mcp-connect as the client
// transport, and the mcp-fs-demo backend. It is skipped when opa is not
// on PATH (or $OPA).
package e2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func opaBinary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("OPA"); p != "" {
		return p
	}
	p, err := exec.LookPath("opa")
	if err != nil {
		t.Skip("opa not found; set $OPA or put opa on PATH")
	}
	return p
}

func build(t *testing.T, dir, pkg string) string {
	t.Helper()
	out := filepath.Join(dir, filepath.Base(pkg))
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = ".."
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building %s: %v\n%s", pkg, err, b)
	}
	return out
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s did not appear", path)
}

// syncBuffer collects a process's stderr.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func start(t *testing.T, name string, args ...string) (*exec.Cmd, *syncBuffer) {
	t.Helper()
	cmd := exec.Command(name, args...)
	logs := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = logs, logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("%s output:\n%s", filepath.Base(name), logs.String())
		}
	})
	return cmd, logs
}

// client speaks newline-delimited JSON-RPC through mcp-connect.
type client struct {
	t     *testing.T
	stdin io.WriteCloser
	lines chan string
}

func newClient(t *testing.T, connect, socket, server string) *client {
	t.Helper()
	cmd := exec.Command(connect, "--socket", socket, "--server", server)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	c := &client{t: t, stdin: stdin, lines: make(chan string, 16)}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64<<10), 16<<20)
		for sc.Scan() {
			c.lines <- sc.Text()
		}
		close(c.lines)
	}()
	return c
}

type msg struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *client) send(v any) {
	c.t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := c.stdin.Write(append(b, '\n')); err != nil {
		c.t.Fatal(err)
	}
}

func (c *client) request(id int, method string, params any) {
	c.t.Helper()
	c.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

func (c *client) read() msg {
	c.t.Helper()
	select {
	case line, ok := <-c.lines:
		if !ok {
			c.t.Fatal("connection closed")
		}
		var m msg
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			c.t.Fatalf("bad message %q: %v", line, err)
		}
		return m
	case <-time.After(10 * time.Second):
		c.t.Fatal("timeout")
	}
	return msg{}
}

func (c *client) call(id int, tool string, args map[string]any) msg {
	c.t.Helper()
	c.request(id, "tools/call", map[string]any{"name": tool, "arguments": args})
	return c.read()
}

func toolResult(t *testing.T, m msg) (string, bool) {
	t.Helper()
	var r struct {
		Content []struct{ Text string }
		IsError bool
	}
	if err := json.Unmarshal(m.Result, &r); err != nil || len(r.Content) == 0 {
		t.Fatalf("not a tool result: id=%s result=%s error=%+v", m.ID, m.Result, m.Error)
	}
	return r.Content[0].Text, r.IsError
}

// env is a running gateway with OPA.
type env struct {
	tmp, connect, gwSock, ctlSock string
	opa                           *exec.Cmd
	gwLogs                        *syncBuffer
}

// setup starts OPA with the shipped policy and rbac as role data, and the
// gateway with one mcp-fs-demo backend per entry of roots (name → root).
// extra is appended to the gateway configuration.
func setup(t *testing.T, rbac string, roots map[string]string, extra string) *env {
	t.Helper()
	opa := opaBinary(t)
	// Unix socket paths are limited to 108 bytes; keep them short.
	tmp, err := os.MkdirTemp("", "mcpgw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmp) })

	bin := filepath.Join(tmp, "bin")
	gateway := build(t, bin, "./cmd/mcp-gateway")
	connect := build(t, bin, "./cmd/mcp-connect")
	demo := build(t, bin, "./examples/mcp-fs-demo")

	writeFile(t, filepath.Join(tmp, "data", "rbac", "data.json"), rbac)
	opaSock := filepath.Join(tmp, "opa.sock")
	opaCmd, _ := start(t, opa, "run", "--server", "--addr", "unix://"+opaSock,
		filepath.Join("..", "policy", "mcp"), filepath.Join(tmp, "data"))
	waitFor(t, opaSock)

	for name, root := range roots {
		writeFile(t, filepath.Join(tmp, "servers.d", name+".yaml"), fmt.Sprintf(
			"name: %s\ncommand: [%q, --root, %q]\nrun_as: gateway\n", name, demo, root))
	}
	gwSock := filepath.Join(tmp, "mcp.sock")
	writeFile(t, filepath.Join(tmp, "gateway.yaml"), fmt.Sprintf(`
socket: %s
servers_dir: %s
state_dir: %s
policy:
  opa_socket: %s
  timeout: 2s
approval_timeout: 5s
supervisor:
  mode: exec
  idle_timeout: 1h
approvals:
  control_socket: %s
  url_template: https://gw.example.com/approvals/{id}
%s`, gwSock, filepath.Join(tmp, "servers.d"), filepath.Join(tmp, "state"), opaSock, filepath.Join(tmp, "control.sock"), extra))
	_, gwLogs := start(t, gateway, "--config", filepath.Join(tmp, "gateway.yaml"))
	waitFor(t, gwSock)
	return &env{tmp: tmp, connect: connect, gwSock: gwSock, ctlSock: filepath.Join(tmp, "control.sock"), opa: opaCmd, gwLogs: gwLogs}
}

func (c *client) initialize(caps map[string]any) msg {
	c.t.Helper()
	c.request(1, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    caps,
		"clientInfo":      map[string]any{"name": "e2e", "version": "1"},
	})
	m := c.read()
	if m.Error != nil {
		c.t.Fatalf("initialize: %+v", m)
	}
	c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	return m
}

func listNames(t *testing.T, m msg, field, key string) string {
	t.Helper()
	var res map[string][]map[string]any
	if err := json.Unmarshal(m.Result, &res); err != nil {
		t.Fatalf("%s: %v (%s)", field, err, m.Result)
	}
	var out []string
	for _, it := range res[field] {
		out = append(out, fmt.Sprint(it[key]))
	}
	return strings.Join(out, ",")
}

func TestEndToEnd(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	home, err := os.MkdirTemp("", "mcpgw-home")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	writeFile(t, filepath.Join(home, "hello.txt"), "hello world")

	// Policy data for this test: the current user is a developer, and
	// writes are confined to the demo home and approved via form.
	rbac := fmt.Sprintf(`{
	  "roles": {"developer": {"permissions": [
	    {"server": "fs", "tool": "read_*"},
	    {"server": "fs", "tool": "list_*"},
	    {"server": "fs", "tool": "write_file", "require_approval": true,
	     "approval_channel": "form", "args": {"path": %q}},
	    {"server": "fs", "tool": "delete_*", "effect": "deny"}
	  ]}},
	  "bindings": {"groups": {}, "users": {%q: ["developer"]}}
	}`, "^"+regexp.QuoteMeta(home)+"/", me.Username)
	e := setup(t, rbac, map[string]string{"fs": home}, "")
	connect, gwSock, gwLogs, opaCmd := e.connect, e.gwSock, e.gwLogs, e.opa

	c := newClient(t, connect, gwSock, "fs")

	c.request(1, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{"elicitation": map[string]any{}},
		"clientInfo":      map[string]any{"name": "e2e", "version": "1"},
	})
	if m := c.read(); m.Error != nil || !strings.Contains(string(m.Result), "mcp-fs-demo") {
		t.Fatalf("initialize: %+v", m)
	}
	c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})

	t.Run("tools/list is filtered", func(t *testing.T) {
		c.request(2, "tools/list", map[string]any{})
		m := c.read()
		var r struct{ Tools []struct{ Name string } }
		if err := json.Unmarshal(m.Result, &r); err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, tool := range r.Tools {
			names = append(names, tool.Name)
		}
		if strings.Join(names, ",") != "list_dir,read_file,write_file" {
			t.Fatalf("tools = %v", names)
		}
	})

	t.Run("allowed read", func(t *testing.T) {
		text, isErr := toolResult(t, c.call(3, "read_file", map[string]any{"path": filepath.Join(home, "hello.txt")}))
		if isErr || text != "hello world" {
			t.Fatalf("got %q isError=%v", text, isErr)
		}
	})

	newFile := filepath.Join(home, "new.txt")
	t.Run("write needs approval", func(t *testing.T) {
		c.request(4, "tools/call", map[string]any{"name": "write_file", "arguments": map[string]any{"path": newFile, "content": "hi"}})
		el := c.read()
		if el.Method != "elicitation/create" || !strings.Contains(string(el.Params), "write_file") {
			t.Fatalf("want elicitation, got %+v", el)
		}
		c.send(map[string]any{"jsonrpc": "2.0", "id": el.ID, "result": map[string]any{"action": "accept", "content": map[string]any{"scope": "session"}}})
		text, isErr := toolResult(t, c.read())
		if isErr || !strings.HasPrefix(text, "wrote") {
			t.Fatalf("got %q isError=%v", text, isErr)
		}
		if b, err := os.ReadFile(newFile); err != nil || string(b) != "hi" {
			t.Fatalf("file content %q, %v", b, err)
		}
	})

	t.Run("session grant reused", func(t *testing.T) {
		text, isErr := toolResult(t, c.call(5, "write_file", map[string]any{"path": newFile, "content": "again"}))
		if isErr || !strings.HasPrefix(text, "wrote") {
			t.Fatalf("got %q isError=%v", text, isErr)
		}
	})

	t.Run("write outside home denied", func(t *testing.T) {
		text, isErr := toolResult(t, c.call(6, "write_file", map[string]any{"path": "/etc/mcpgw-test", "content": "x"}))
		if !isErr || !strings.Contains(text, "mcp-gateway") {
			t.Fatalf("got %q isError=%v", text, isErr)
		}
	})

	t.Run("delete denied", func(t *testing.T) {
		text, isErr := toolResult(t, c.call(7, "delete_file", map[string]any{"path": newFile}))
		if !isErr || !strings.Contains(text, "denied by policy") {
			t.Fatalf("got %q isError=%v", text, isErr)
		}
		if _, err := os.Stat(newFile); err != nil {
			t.Fatal("file was deleted")
		}
	})

	t.Run("resources/read denied", func(t *testing.T) {
		c.request(8, "resources/read", map[string]any{"uri": "file:///etc/passwd"})
		if m := c.read(); m.Error == nil || m.Error.Code != -32001 {
			t.Fatalf("got %+v", m)
		}
	})

	t.Run("audit records", func(t *testing.T) {
		logs := gwLogs.String()
		for _, want := range []string{`"effect":"allow"`, `"effect":"deny"`, `"grant":"g-`, `"args_sha256"`} {
			if !strings.Contains(logs, want) {
				t.Errorf("gateway logs lack %s", want)
			}
		}
	})

	t.Run("fails closed without OPA", func(t *testing.T) {
		_ = opaCmd.Process.Kill()
		_ = opaCmd.Wait()
		text, isErr := toolResult(t, c.call(9, "read_file", map[string]any{"path": filepath.Join(home, "hello.txt")}))
		if !isErr || !strings.Contains(text, "policy evaluation failed") {
			t.Fatalf("got %q isError=%v", text, isErr)
		}
	})
}

func TestAggregatedEndpoint(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	base, err := os.MkdirTemp("", "mcpgw-roots")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	home, notes := filepath.Join(base, "home"), filepath.Join(base, "notes")
	writeFile(t, filepath.Join(home, "hello.txt"), "hello world")
	writeFile(t, filepath.Join(notes, "todo.txt"), "buy milk")

	rbac := fmt.Sprintf(`{
	  "roles": {"developer": {"permissions": [
	    {"server": "*", "tool": "read_*"},
	    {"server": "fs", "tool": "list_*"},
	    {"server": "fs", "resource": %q},
	    {"server": "*", "prompt": "*"}
	  ]}},
	  "bindings": {"groups": {}, "users": {%q: ["developer"]}}
	}`, "file://"+home+"/*", me.Username)
	e := setup(t, rbac, map[string]string{"fs": home, "notes": notes}, "")

	// No --server: the aggregated endpoint.
	c := newClient(t, e.connect, e.gwSock, "all")
	init := c.initialize(map[string]any{})
	if !strings.Contains(string(init.Result), `"name":"mcp-gateway"`) {
		t.Fatalf("initialize: %s", init.Result)
	}

	t.Run("tools are namespaced and filtered", func(t *testing.T) {
		c.request(2, "tools/list", map[string]any{})
		if got := listNames(t, c.read(), "tools", "name"); got != "fs__list_dir,fs__read_file,notes__read_file" {
			t.Fatalf("tools = %s", got)
		}
	})

	t.Run("calls are routed", func(t *testing.T) {
		text, isErr := toolResult(t, c.call(3, "notes__read_file", map[string]any{"path": "todo.txt"}))
		if isErr || text != "buy milk" {
			t.Fatalf("got %q isError=%v", text, isErr)
		}
		text, isErr = toolResult(t, c.call(4, "notes__write_file", map[string]any{"path": "x", "content": "x"}))
		if !isErr || !strings.Contains(text, "no matching permission") {
			t.Fatalf("got %q isError=%v", text, isErr)
		}
	})

	fsURI := "mcp+fs:file://" + filepath.Join(home, "hello.txt")
	t.Run("resources are namespaced and filtered", func(t *testing.T) {
		c.request(5, "resources/list", map[string]any{})
		if got := listNames(t, c.read(), "resources", "uri"); got != fsURI {
			t.Fatalf("resources = %s (notes resources must be hidden)", got)
		}
		c.request(6, "resources/read", map[string]any{"uri": fsURI})
		m := c.read()
		if !strings.Contains(string(m.Result), "hello world") || !strings.Contains(string(m.Result), fsURI) {
			t.Fatalf("read: %s %+v", m.Result, m.Error)
		}
		c.request(7, "resources/read", map[string]any{"uri": "mcp+notes:file://" + filepath.Join(notes, "todo.txt")})
		if m := c.read(); m.Error == nil || m.Error.Code != -32001 {
			t.Fatalf("notes read: %+v", m)
		}
	})

	t.Run("prompts are namespaced", func(t *testing.T) {
		c.request(8, "prompts/list", map[string]any{})
		if got := listNames(t, c.read(), "prompts", "name"); got != "fs__summarize_file,notes__summarize_file" {
			t.Fatalf("prompts = %s", got)
		}
		c.request(9, "prompts/get", map[string]any{"name": "notes__summarize_file", "arguments": map[string]any{"path": "todo.txt"}})
		if m := c.read(); !strings.Contains(string(m.Result), "Summarize the file at todo.txt") {
			t.Fatalf("prompts/get: %s %+v", m.Result, m.Error)
		}
	})

	t.Run("instances are shared by the principal's sessions", func(t *testing.T) {
		c2 := newClient(t, e.connect, e.gwSock, "fs")
		c2.initialize(map[string]any{})
		text, _ := toolResult(t, c2.call(2, "read_file", map[string]any{"path": filepath.Join(home, "hello.txt")}))
		if text != "hello world" {
			t.Fatalf("got %q", text)
		}
		if n := strings.Count(e.gwLogs.String(), `msg="instance started" server=fs`); n != 1 {
			t.Fatalf("fs instance started %d times, want 1\n%s", n, e.gwLogs.String())
		}
	})
}
