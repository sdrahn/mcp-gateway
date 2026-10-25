package e2e

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/webhook"
)

// TestApprovalWebhooks (stage E): the gateway posts a pending approval to
// a webhook, signed and without the arguments; a signed callback naming
// an approver the rules allow decides it, and the waiting call runs. An
// unsigned callback, one naming someone the rules do not allow and a
// replayed one are refused; the audit names the webhook and the approver.
func TestApprovalWebhooks(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	home, err := os.MkdirTemp("", "mcpgw-webhook")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	secret := []byte("e2e-webhook-secret-0123456789abcdef")
	secretFile := filepath.Join(home, "chat.secret")
	if err := os.WriteFile(secretFile, append(secret, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	type post struct {
		kind string
		body []byte
		err  error
	}
	posts := make(chan post, 10)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, err := webhook.Verify(secret, b, r.Header.Get(webhook.SignatureHeader), time.Now())
		posts <- post{r.Header.Get(webhook.EventHeader), b, err}
	}))
	t.Cleanup(receiver.Close)

	provider := newIdP(t)
	certFile, keyFile, pool := selfSigned(t, home)
	port := freePort(t)
	origin := fmt.Sprintf("https://127.0.0.1:%d", port)
	rbac := fmt.Sprintf(`{
	  "roles": {"developer": {"permissions": [
	    {"server": "fs", "tool": "write_file", "require_approval": true, "approval_channel": "oob", "approval_scopes": ["once"]}
	  ]}},
	  "bindings": {"groups": {}, "users": {%q: ["developer"]}},
	  "approvers": {"fs": ["remote-user:chat-approver"]}
	}`, me.Username)
	e := setup(t, rbac, map[string]string{"fs": home}, fmt.Sprintf(`http:
  listen: 127.0.0.1:%d
  cert_file: %s
  key_file: %s
  issuer: %s
  audience: %s/mcp
approvals:
  webhooks:
    - name: chat
      url: %s/hook
      secret_file: %s
`, port, certFile, keyFile, provider.srv.URL, origin, receiver.URL, secretFile))

	c := newClient(t, e.connect, e.gwSock, "fs")
	c.initialize(map[string]any{})
	target := filepath.Join(home, "hooked.txt")
	c.request(2, "tools/call", map[string]any{"name": "write_file",
		"arguments": map[string]any{"path": target, "content": "do not post this"}})

	var p post
	select {
	case p = <-posts:
	case <-time.After(15 * time.Second):
		t.Fatalf("nothing posted\n%s", e.gwLogs.String())
	}
	if p.err != nil || p.kind != "pending" {
		t.Fatalf("post %s: %v %s", p.kind, p.err, p.body)
	}
	if bytes.Contains(p.body, []byte("do not post this")) || bytes.Contains(p.body, []byte(`"args"`)) {
		t.Errorf("the arguments were posted: %s", p.body)
	}
	var ev webhook.Event
	if err := json.Unmarshal(p.body, &ev); err != nil || ev.Call == nil || ev.Call.Tool != "write_file" || ev.Call.Principal != me.Username {
		t.Fatalf("post %s: %v", p.body, err)
	}
	if want := origin + "/approvals/webhook/chat"; ev.Callback != want {
		t.Fatalf("callback %q, want %q", ev.Callback, want)
	}

	https := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	callback := func(body string, sign bool) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, ev.Callback, strings.NewReader(body))
		if sign {
			req.Header.Set(webhook.SignatureHeader, webhook.Sign(secret, []byte(body), time.Now()))
		}
		resp, err := https.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	decide := func(approver string) string {
		return fmt.Sprintf(`{"id":%q,"decision":"approve","scope":"once","approver":%q}`, ev.ID, approver)
	}
	if code, b := callback(decide("remote-user:chat-approver"), false); code != 401 {
		t.Errorf("unsigned: %d %s", code, b)
	}
	if code, b := callback(decide("remote-user:someone-else"), true); code != 404 {
		t.Errorf("not an approver: %d %s", code, b)
	}
	approve := decide("remote-user:chat-approver")
	sig := webhook.Sign(secret, []byte(approve), time.Now())
	signedCall := func() (int, string) {
		req, _ := http.NewRequest(http.MethodPost, ev.Callback, strings.NewReader(approve))
		req.Header.Set(webhook.SignatureHeader, sig)
		resp, err := https.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, b := signedCall(); code != 200 || !strings.Contains(b, `"approved_by":"chat-approver"`) {
		t.Fatalf("approve: %d %s\n%s", code, b, e.gwLogs.String())
	}
	if code, b := signedCall(); code != 409 {
		t.Errorf("replayed: %d %s", code, b)
	}

	var result msg
	for result.ID == nil || string(result.ID) != "2" {
		result = c.read()
	}
	if text, isErr := toolResult(t, result); isErr || !strings.HasPrefix(text, "wrote") {
		t.Fatalf("the call: %q %v", text, isErr)
	}
	select {
	case p = <-posts:
		if p.kind != "resolved" || !bytes.Contains(p.body, []byte(ev.ID)) {
			t.Errorf("after the decision: %s %s", p.kind, p.body)
		}
	case <-time.After(10 * time.Second):
		t.Error("the decision was not posted")
	}
	logs := e.gwLogs.String()
	for _, want := range []string{`"event":"mcp-webhook-callback"`, `"webhook":"chat"`, `"approver":"remote-user:chat-approver"`,
		`"approver":"remote-user:someone-else"`, `"via":"webhook"`, `"by":"chat-approver"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("audit lacks %s", want)
		}
	}
}
