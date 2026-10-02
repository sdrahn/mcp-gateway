package e2e

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSessionLimitHTTP: at limits.sessions_per_principal, a new HTTP
// session of the same principal ends its longest-idle one (which clients
// such as Kit leave behind); that one then gets 404 (decision D14).
func TestSessionLimitHTTP(t *testing.T) {
	home, err := os.MkdirTemp("", "mcpgw-limits")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	writeFile(t, filepath.Join(home, "hello.txt"), "hello")

	provider := newIdP(t)
	certFile, keyFile, pool := selfSigned(t, home)
	port := freePort(t)
	audience := fmt.Sprintf("https://127.0.0.1:%d/mcp", port)
	rbac := `{"roles": {"reader": {"permissions": [{"server": "fs", "tool": "read_*"}]}},
	  "bindings": {"groups": {}, "users": {"u-remote": ["reader"]}}}`
	e := setup(t, rbac, map[string]string{"fs": home}, fmt.Sprintf(`limits:
  sessions_per_principal: 2
http:
  listen: 127.0.0.1:%d
  cert_file: %s
  key_file: %s
  issuer: %s
  audience: %s
  scopes: [mcp]
`, port, certFile, keyFile, provider.srv.URL, audience))
	waitHTTPS(t, port)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	token := provider.token(t, "u-remote", audience)
	open := func() *remote {
		c := &remote{t: t, client: client, url: audience + "/fs", token: token}
		m := c.call(1, "initialize", map[string]any{
			"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "limits-e2e"},
		})
		if m.Error != nil || c.session == "" {
			t.Fatalf("initialize: %+v (session %q)", m.Error, c.session)
		}
		resp := c.post(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, false)
		_ = resp.Body.Close()
		return c
	}
	first := open()
	time.Sleep(50 * time.Millisecond) // the first is the longest idle
	second := open()
	third := open()

	resp := first.post(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": map[string]any{}}, false)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("the idle session after the limit: HTTP %d, want 404", resp.StatusCode)
	}
	for _, c := range []*remote{second, third} {
		if m := c.call(2, "tools/list", map[string]any{}); m.Error != nil {
			t.Fatalf("session %s: %+v", c.session, m.Error)
		}
	}
	if !strings.Contains(e.gwLogs.String(), "ended an idle session for a new one at the session limit") {
		t.Errorf("no log line for the ended session:\n%s", e.gwLogs.String())
	}

	// With a stream attached, a session is in use: nothing makes room,
	// and the new session's initialize gets the error.
	for _, c := range []*remote{second, third} {
		req, _ := http.NewRequest(http.MethodGet, c.url, nil)
		req.Header.Set("Accept", "text/event-stream")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Mcp-Session-Id", c.session)
		req.Header.Set("MCP-Protocol-Version", "2025-06-18")
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("GET stream: %v %v", err, resp)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
	}
	time.Sleep(100 * time.Millisecond) // the streams are attached
	refused := &remote{t: t, client: client, url: audience + "/fs", token: token}
	m := refused.call(1, "initialize", map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "limits-e2e"},
	})
	if m.Error == nil || !strings.Contains(m.Error.Message, "session limit reached (2)") {
		t.Fatalf("initialize at the limit: %+v", m)
	}
}
