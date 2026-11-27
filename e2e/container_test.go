package e2e

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// echoServer is a server that speaks Streamable HTTP (JSON responses
// only) with one tool, echo.
func echoServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if m.ID == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		var result any
		switch m.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{"name": "echo", "version": "1"}}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{"name": "echo", "inputSchema": map[string]any{
				"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}}}}}
		case "tools/call":
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": fmt.Sprint("echo: ", m.Params.Arguments["text"])}}}
		default:
			result = map[string]any{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// In container mode (deployment: container) the gateway has no Unix
// socket and serves remote principals over HTTP; a server that speaks
// HTTP is reached through its connector, a child process; a stdio server
// is refused with the reason.
func TestContainerMode(t *testing.T) {
	dir := t.TempDir()
	provider := newIdP(t)
	certFile, keyFile, pool := selfSigned(t, dir)
	port := freePort(t)
	audience := fmt.Sprintf("https://127.0.0.1:%d/mcp", port)
	rbac := `{
	  "roles": {"echoer": {"permissions": [{"server": "echo", "tool": "echo"}]}},
	  "bindings": {"groups": {}, "users": {"u-agent": ["echoer"]}}
	}`
	e := setup(t, rbac, nil, fmt.Sprintf(`deployment: container
http:
  listen: 127.0.0.1:%d
  cert_file: %s
  key_file: %s
  issuer: %s
  audience: %s
`, port, certFile, keyFile, provider.srv.URL, audience))
	if _, err := os.Stat(e.gwSock); !os.IsNotExist(err) {
		t.Fatalf("a Unix socket in container mode: %v", err)
	}
	if !strings.Contains(e.gwLogs.String(), "container mode: no Unix socket") {
		t.Errorf("no word of container mode in the logs:\n%s", e.gwLogs.String())
	}
	libexec := filepath.Join(e.tmp, "libexec", "mcp-gateway")
	build(t, libexec, "./cmd/mcp-http-connector")
	echo := echoServer(t)
	writeFile(t, filepath.Join(e.tmp, "servers.d", "echo.yaml"), fmt.Sprintf("name: echo\nurl: %s/mcp\n", echo.URL))

	ctl := controlClient(e.ctlSock)
	deadline := time.Now().Add(15 * time.Second)
	for {
		var servers []struct{ Name string }
		controlDo(t, ctl, "GET", "/v1/servers", "", &servers)
		if len(servers) == 1 && servers[0].Name == "echo" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("echo not loaded:\n%s", e.gwLogs.String())
		}
		time.Sleep(200 * time.Millisecond)
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	c := &remote{t: t, client: client, url: audience + "/echo", token: provider.token(t, "u-agent", audience)}
	deadline = time.Now().Add(15 * time.Second)
	for {
		resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/.well-known/oauth-protected-resource/mcp", port))
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway HTTPS not up: %v\n%s", err, e.gwLogs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	m := c.call(1, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "container-e2e"}})
	if m.Error != nil || c.session == "" {
		t.Fatalf("initialize: %s %v", m.Result, m.Error)
	}
	resp := c.post(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, false)
	_ = resp.Body.Close()
	text, isErr := toolResult(t, c.call(2, "tools/call", map[string]any{"name": "echo", "arguments": map[string]any{"text": "hi"}}))
	if isErr || text != "echo: hi" {
		t.Fatalf("echo: %q %v\n%s", text, isErr, e.gwLogs.String())
	}

	// A stdio server is refused, in mcp-gateway --check and on reload.
	stdio := filepath.Join(e.tmp, "servers.d", "fs.yaml")
	writeFile(t, stdio, "name: fs\ncommand: [/usr/bin/true]\n")
	out, err := exec.Command(e.gwBin, "--config", e.gwConfig, "--check").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "server fs: command: not in container mode") {
		t.Fatalf("--check with a stdio server: %v\n%s", err, out)
	}
	deadline = time.Now().Add(15 * time.Second)
	for !strings.Contains(e.gwLogs.String(), "server fs: command: not in container mode") {
		if time.Now().After(deadline) {
			t.Fatalf("the reload did not refuse fs:\n%s", e.gwLogs.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
	var servers []struct{ Name string }
	controlDo(t, ctl, "GET", "/v1/servers", "", &servers)
	if len(servers) != 1 || servers[0].Name != "echo" {
		t.Errorf("servers after the refused reload: %+v", servers)
	}
}
