package e2e

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
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
// is refused with the reason. An agent in the cluster presents a token
// of the cluster's issuer (http.issuers), a person one of the
// organization's.
func TestContainerMode(t *testing.T) {
	dir := t.TempDir()
	provider, cluster := newIdP(t), newIdP(t)
	certFile, keyFile, pool := selfSigned(t, dir)
	port := freePort(t)
	audience := fmt.Sprintf("https://127.0.0.1:%d/mcp", port)
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	// The test's account is an operator (review_policy): it sees the
	// doctor's results.
	rbac := fmt.Sprintf(`{
	  "roles": {"echoer": {"permissions": [{"server": "echo", "tool": "echo"}]}},
	  "bindings": {"groups": {}, "users": {"u-agent": ["echoer"], "k8s:system:serviceaccount:agents:custos": ["echoer"]}},
	  "approvers": {"default": ["user:%s"]}
	}`, me.Username)
	e := setup(t, rbac, nil, fmt.Sprintf(`deployment: container
http:
  listen: 127.0.0.1:%d
  cert_file: %s
  key_file: %s
  issuer: %s
  audience: %s
  issuers:
    - issuer: %s
      audience: mcp-gateway
      scopes: []
      subject_prefix: "k8s:"
`, port, certFile, keyFile, provider.srv.URL, audience, cluster.srv.URL))
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
			var meta struct {
				AuthorizationServers []string `json:"authorization_servers"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&meta)
			_ = resp.Body.Close()
			if len(meta.AuthorizationServers) != 2 || meta.AuthorizationServers[0] != provider.srv.URL || meta.AuthorizationServers[1] != cluster.srv.URL {
				t.Fatalf("authorization servers: %v", meta.AuthorizationServers)
			}
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

	// A ServiceAccount's token of the cluster's issuer: its audience, no
	// scope, its subject with the prefix the role data binds.
	saToken := cluster.tokenWith(t, "system:serviceaccount:agents:custos", "mcp-gateway", map[string]any{"scope": nil})
	sa := &remote{t: t, client: client, url: audience + "/echo", token: saToken}
	sa.call(1, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "container-e2e-sa"}})
	resp = sa.post(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, false)
	_ = resp.Body.Close()
	if text, isErr := toolResult(t, sa.call(2, "tools/call", map[string]any{"name": "echo", "arguments": map[string]any{"text": "sa"}})); isErr || text != "echo: sa" {
		t.Fatalf("echo as the ServiceAccount: %q %v\n%s", text, isErr, e.gwLogs.String())
	}
	// The cluster's token for the organization's audience is refused.
	wrong := &remote{t: t, client: client, url: audience + "/echo", token: cluster.tokenWith(t, "system:serviceaccount:agents:custos", audience, nil)}
	resp = wrong.post(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{}}, false)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the cluster's token for another audience: HTTP %d", resp.StatusCode)
	}

	// The doctor in the gateway: run on request, over the control socket.
	var rep struct {
		Trigger string
		Results []struct{ Check, ID, Subject, Status, Summary string }
	}
	if code := controlDo(t, ctl, "POST", "/v1/doctor", "", &rep); code != 200 || rep.Trigger != "request" {
		t.Fatalf("doctor: %d %+v", code, rep)
	}
	got := map[string]string{}
	for _, r := range rep.Results {
		got[r.Check] = r.Status
		if r.Status == "fail" {
			t.Errorf("doctor: %s failed: %s", r.Check, r.Summary)
		}
	}
	for _, check := range []string{"configuration", "policy", "identity provider " + provider.srv.URL, "identity provider " + cluster.srv.URL,
		"server echo", "state volume"} {
		if got[check] != "ok" {
			t.Errorf("doctor: %s is %q, want ok (%v)", check, got[check], got)
		}
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
