package e2e

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestApprovalPageBrowser approves on the gateway's approval page in a
// real browser (test/browser/approval-page.js, headless Chromium through
// Playwright): signed in through the identity provider, the Approve button
// pressed, the call runs; signing out signs out at the identity provider
// too, and the next sign-in asks for the password again. The other page tests post the form themselves,
// with the Origin they choose; a browser chooses its own, by the page's
// referrer policy (1.9.0's no-referrer made it send "Origin: null", and
// the page refused every decision as from another site).
//
// MCPGW_BROWSER=1 runs it, with node and playwright-core (or playwright)
// found by node; CHROME names a Chrome or Chromium binary (else
// Playwright's own).
func TestApprovalPageBrowser(t *testing.T) {
	if os.Getenv("MCPGW_BROWSER") == "" {
		t.Skip("MCPGW_BROWSER=1 runs it (node, playwright-core, Chrome)")
	}
	script, err := filepath.Abs(filepath.Join("..", "test", "browser", "approval-page.js"))
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.MkdirTemp("", "mcpgw-browser")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	provider, flow := newCodeFlowIdP(t)
	certFile, keyFile, pool := selfSigned(t, home)
	port := freePort(t)
	origin := fmt.Sprintf("https://127.0.0.1:%d", port)
	audience := origin + "/mcp"
	flow.redirectURI = origin + "/approvals/callback"
	flow.user = "u-approver"

	rbac := fmt.Sprintf(`{
	  "roles": {"writer": {"permissions": [
	    {"server": "fs", "tool": "write_file", "require_approval": true, "approval_channel": "url",
	     "approval_scopes": ["once"], "args": {"path": %q}}
	  ]}},
	  "bindings": {"groups": {}, "users": {"u-agent": ["writer"]}},
	  "approvers": {"fs": ["remote-user:u-approver"]}
	}`, "^"+regexp.QuoteMeta(home)+"/")
	// The approval waits for the browser to start and sign in: longer
	// than the other tests' 5s on a busy runner.
	e := setup(t, rbac, map[string]string{"fs": home}, fmt.Sprintf(`approval_timeout: 2m
http:
  listen: 127.0.0.1:%d
  cert_file: %s
  key_file: %s
  issuer: %s
  audience: %s
approvals:
  page:
    client_id: approvals
`, port, certFile, keyFile, provider.srv.URL, audience))

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := client.Get(audience)
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway HTTPS not up: %v\n%s", err, e.gwLogs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	agent := &remote{t: t, client: client, url: audience + "/fs", token: provider.token(t, "u-agent", audience)}
	agent.call(1, "initialize", map[string]any{"protocolVersion": "2025-06-18",
		"capabilities": map[string]any{"elicitation": map[string]any{"url": map[string]any{}}},
		"clientInfo":   map[string]any{"name": "browser-e2e"}})
	_ = agent.post(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, false).Body.Close()
	target := filepath.Join(home, "browser.txt")
	events := sse(t, agent.post(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{
		"name": "write_file", "arguments": map[string]any{"path": target, "content": "approved in a browser"}}}, true))
	el := nextEvent(t, events)
	var params struct{ Mode, URL string }
	_ = json.Unmarshal(el.Params, &params)
	if el.Method != "elicitation/create" || !strings.HasPrefix(params.URL, origin+"/approvals/a-") {
		t.Fatalf("want a URL elicitation for the page, got %s %s", el.Method, el.Params)
	}
	_ = agent.post(map[string]any{"jsonrpc": "2.0", "id": el.ID, "result": map[string]any{"action": "accept"}}, false).Body.Close()

	cmd := exec.Command("node", script, params.URL)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	t.Logf("browser:\n%s", out)
	if err != nil {
		t.Fatalf("the browser: %v", err)
	}
	if !strings.Contains(string(out), "post "+strings.TrimPrefix(params.URL, origin)+" origin="+origin) {
		t.Errorf("the browser did not send the page's origin with the decision")
	}
	if !strings.Contains(string(out), "Done: approved") {
		t.Fatalf("the page did not take the decision\n%s", e.gwLogs.String())
	}
	if !strings.Contains(string(out), "signed out: ") || !strings.Contains(string(out), "signed out of the approval page and of the identity provider") {
		t.Errorf("signing out did not go through the identity provider")
	}
	flow.mu.Lock()
	prompts, signOuts := flow.prompts, flow.signOuts
	flow.mu.Unlock()
	// The sign-in after signing out asks for the password again.
	if signOuts != 1 || !slices.Equal(prompts, []string{"", "login"}) {
		t.Errorf("sign-outs %d, prompts %q", signOuts, prompts)
	}
	var result msg
	for result.ID == nil || string(result.ID) != "2" {
		result = nextEvent(t, events)
	}
	if text, isErr := toolResult(t, result); isErr || !strings.HasPrefix(text, "wrote") {
		t.Fatalf("the call: %q %v", text, isErr)
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "approved in a browser" {
		t.Fatalf("file %q %v", b, err)
	}
	if logs := e.gwLogs.String(); !strings.Contains(logs, `"via":"page"`) || !strings.Contains(logs, `"by":"u-approver"`) {
		t.Errorf("audit lacks the page's decision")
	}
}
