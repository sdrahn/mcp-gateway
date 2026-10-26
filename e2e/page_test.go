package e2e

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// codeFlow adds the authorization code flow with PKCE to the test
// identity provider, for the approval page: whoever User names signs in
// at once; codes are bound to the client, redirect URI and challenge.
type codeFlow struct {
	i           *idp
	clientID    string
	redirectURI string
	mu          sync.Mutex
	user        string
	codes       map[string][2]string // code: challenge, nonce
	// The device flow (stage D) for the client approvals-cli: confirmed
	// says whether the code was confirmed, as deviceUser.
	confirmed  bool
	deviceUser string
	// prompts records the prompt of each authorization, signOuts the
	// sign-outs at its end_session_endpoint.
	prompts  []string
	signOuts int
}

// idToken is an ID token for aud.
func (cf *codeFlow) idToken(sub, aud string, extra jwt.MapClaims) (string, error) {
	c := jwt.MapClaims{"iss": cf.i.srv.URL, "aud": aud, "sub": sub, "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()}
	for k, v := range extra {
		c[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = "k1"
	return tok.SignedString(cf.i.key)
}

func newCodeFlowIdP(t *testing.T) (*idp, *codeFlow) {
	t.Helper()
	i := newIdP(t)
	cf := &codeFlow{i: i, clientID: "approvals", codes: map[string][2]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": i.srv.URL, "jwks_uri": i.srv.URL + "/jwks",
			"authorization_endpoint": i.srv.URL + "/authorize", "token_endpoint": i.srv.URL + "/token",
			"device_authorization_endpoint":    i.srv.URL + "/device",
			"end_session_endpoint":             i.srv.URL + "/logout",
			"code_challenge_methods_supported": []string{"S256"}})
	})
	mux.HandleFunc("POST /device", func(w http.ResponseWriter, r *http.Request) {
		if r.PostFormValue("client_id") != "approvals-cli" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "dc-1", "user_code": "WXYZ-1234",
			"verification_uri": i.srv.URL + "/device", "expires_in": 60, "interval": 1})
	})
	mux.Handle("/jwks", i.srv.Config.Handler)
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		after := strings.TrimSuffix(cf.redirectURI, "/callback") + "/signed-out"
		if q.Get("client_id") != cf.clientID || q.Get("post_logout_redirect_uri") != after || q.Get("id_token_hint") == "" {
			http.Error(w, "bad sign-out request", http.StatusBadRequest)
			return
		}
		cf.mu.Lock()
		cf.signOuts++
		cf.mu.Unlock()
		http.Redirect(w, r, after, http.StatusFound)
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != cf.clientID || q.Get("redirect_uri") != cf.redirectURI || q.Get("code_challenge_method") != "S256" {
			http.Error(w, "bad authorization request", http.StatusBadRequest)
			return
		}
		code := fmt.Sprintf("c%d", time.Now().UnixNano())
		cf.mu.Lock()
		cf.prompts = append(cf.prompts, q.Get("prompt"))
		cf.codes[code] = [2]string{q.Get("code_challenge"), q.Get("nonce")}
		cf.mu.Unlock()
		http.Redirect(w, r, cf.redirectURI+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.PostFormValue("grant_type") == "urn:ietf:params:oauth:grant-type:device_code" {
			cf.mu.Lock()
			ok, user := cf.confirmed, cf.deviceUser
			cf.mu.Unlock()
			if !ok || r.PostFormValue("device_code") != "dc-1" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
				return
			}
			s, err := cf.idToken(user, "approvals-cli", nil)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "access_token": "x", "id_token": s})
			return
		}
		cf.mu.Lock()
		c, ok := cf.codes[r.PostFormValue("code")]
		delete(cf.codes, r.PostFormValue("code"))
		user := cf.user
		cf.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != c[0] || r.PostFormValue("client_id") != cf.clientID {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": i.srv.URL, "aud": cf.clientID, "sub": user,
			"nonce": c[1], "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix()})
		tok.Header["kid"] = "k1"
		s, err := tok.SignedString(i.key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "access_token": "x", "id_token": s})
	})
	i.srv.Config.Handler = mux
	return i, cf
}

// TestApprovalPage: a remote agent's call that needs an approval (url
// channel) gets the gateway's own page as the approval URL, as
// url_template defaults to it; an approver the approver rules name
// signs in there with the identity provider and approves; the call runs.
// Another remote user signs in too but sees and decides nothing: the
// rule "user:u-other" names a local account u-other, which a remote
// sign-in without a local account never is.
func TestApprovalPage(t *testing.T) {
	home, err := os.MkdirTemp("", "mcpgw-page")
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

	rbac := fmt.Sprintf(`{
	  "roles": {"writer": {"permissions": [
	    {"server": "fs", "tool": "write_file", "require_approval": true, "approval_channel": "url",
	     "approval_scopes": ["once"], "args": {"path": %q}}
	  ]}},
	  "bindings": {"groups": {}, "users": {"u-agent": ["writer"]}},
	  "approvers": {"fs": ["remote-user:u-approver", "user:u-other"]}
	}`, "^"+regexp.QuoteMeta(home)+"/")
	e := setup(t, rbac, map[string]string{"fs": home}, fmt.Sprintf(`http:
  listen: 127.0.0.1:%d
  cert_file: %s
  key_file: %s
  issuer: %s
  audience: %s
approvals:
  page:
    client_id: approvals
`, port, certFile, keyFile, provider.srv.URL, audience))

	tlsConf := &tls.Config{RootCAs: pool}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}}
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
	browser := func(user string) *http.Client {
		jar, _ := cookiejar.New(nil)
		flow.mu.Lock()
		flow.user = user
		flow.mu.Unlock()
		return &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: tlsConf}}
	}
	get := func(c *http.Client, u string) (int, string) {
		t.Helper()
		resp, err := c.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	agent := &remote{t: t, client: client, url: audience + "/fs", token: provider.token(t, "u-agent", audience)}
	agent.call(1, "initialize", map[string]any{"protocolVersion": "2025-06-18",
		"capabilities": map[string]any{"elicitation": map[string]any{"url": map[string]any{}}},
		"clientInfo":   map[string]any{"name": "page-e2e"}})
	_ = agent.post(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, false).Body.Close()
	target := filepath.Join(home, "approved.txt")
	resp := agent.post(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{
		"name": "write_file", "arguments": map[string]any{"path": target, "content": "via the page"}}}, true)
	events := sse(t, resp)
	el := nextEvent(t, events)
	var params struct {
		Mode, URL string
	}
	_ = json.Unmarshal(el.Params, &params)
	if el.Method != "elicitation/create" || params.Mode != "url" || !strings.HasPrefix(params.URL, origin+"/approvals/a-") {
		t.Fatalf("want a URL elicitation for the gateway's page, got %s %s", el.Method, el.Params)
	}
	ack := agent.post(map[string]any{"jsonrpc": "2.0", "id": el.ID, "result": map[string]any{"action": "accept"}}, false)
	_ = ack.Body.Close()

	// u-other, remote without a local account: "user:u-other" is not
	// theirs; signed in, they see nothing.
	other := browser("u-other")
	if code, body := get(other, params.URL); code != http.StatusNotFound || !strings.Contains(body, "not yours to decide") {
		t.Fatalf("u-other opens it: %d %s", code, body)
	}

	approver := browser("u-approver")
	code, body := get(approver, params.URL)
	if code != http.StatusOK || !strings.Contains(body, "fs/write_file") || !strings.Contains(body, "via the page") ||
		!strings.Contains(body, "page-e2e") || !strings.Contains(body, "Signed in as <b>u-approver</b>") {
		t.Fatalf("approver opens it: %d %s\n%s", code, body, e.gwLogs.String())
	}
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(body)
	if csrf == nil {
		t.Fatal("no CSRF token")
	}
	form := url.Values{"decision": {"approve"}, "scope": {"once"}, "csrf": {csrf[1]}}
	req, _ := http.NewRequest(http.MethodPost, params.URL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	decided, err := approver.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(decided.Body)
	_ = decided.Body.Close()
	if decided.StatusCode != http.StatusOK || !strings.Contains(string(b), "Done: approved") {
		t.Fatalf("approve: %d %s", decided.StatusCode, b)
	}
	var result msg
	for result.ID == nil || string(result.ID) != "2" {
		result = nextEvent(t, events)
	}
	if text, isErr := toolResult(t, result); isErr || !strings.HasPrefix(text, "wrote") {
		t.Fatalf("the call: %q %v", text, isErr)
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "via the page" {
		t.Fatalf("file %q %v", b, err)
	}
	logs := e.gwLogs.String()
	for _, want := range []string{`"event":"mcp-approver-sign-in"`, `"principal":"u-approver"`, `"event":"mcp-approval"`, `"via":"page"`, `"by":"u-approver"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("audit lacks %s", want)
		}
	}
}

// TestApprovalsFromAnotherHost (stage D): mcp-gateway-admin approvals
// --gateway, as on a laptop: signed in with the device flow, it lists and
// approves a remote agent's call on the gateway's approval API, under the
// same approver rules; an agent's token and another client's are not a
// sign-in there.
func TestApprovalsFromAnotherHost(t *testing.T) {
	home, err := os.MkdirTemp("", "mcpgw-remote-cli")
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
	rbac := fmt.Sprintf(`{
	  "roles": {"writer": {"permissions": [
	    {"server": "fs", "tool": "write_file", "require_approval": true, "approval_channel": "url",
	     "approval_scopes": ["once"], "args": {"path": %q}}
	  ]}},
	  "bindings": {"groups": {}, "users": {"u-agent": ["writer"]}},
	  "approvers": {"fs": ["remote-user:u-approver"]}
	}`, "^"+regexp.QuoteMeta(home)+"/")
	e := setup(t, rbac, map[string]string{"fs": home}, fmt.Sprintf(`http:
  listen: 127.0.0.1:%d
  cert_file: %s
  key_file: %s
  issuer: %s
  audience: %s
approvals:
  page:
    client_id: approvals
    device_client_id: approvals-cli
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
	admin := build(t, filepath.Join(e.tmp, "bin"), "./cmd/mcp-gateway-admin")
	cli := func(args ...string) (int, string) {
		cmd := exec.Command(admin, args...)
		cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+certFile, "XDG_CONFIG_HOME="+filepath.Join(home, "config"))
		out, err := cmd.CombinedOutput()
		rc := 0
		if ee, ok := err.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return rc, string(out)
	}

	// Sign in: the code is confirmed while the command waits.
	flow.mu.Lock()
	flow.deviceUser = "u-approver"
	flow.mu.Unlock()
	go func() {
		time.Sleep(1500 * time.Millisecond)
		flow.mu.Lock()
		flow.confirmed = true
		flow.mu.Unlock()
	}()
	rc, out := cli("approvals", "login", "--gateway", origin)
	if rc != 0 || !strings.Contains(out, "confirm the code WXYZ-1234") || !strings.Contains(out, "signed in to "+origin+" as u-approver") {
		t.Fatalf("login: %d %s\n%s", rc, out, e.gwLogs.String())
	}

	agent := &remote{t: t, client: client, url: audience + "/fs", token: provider.token(t, "u-agent", audience)}
	agent.call(1, "initialize", map[string]any{"protocolVersion": "2025-06-18",
		"capabilities": map[string]any{"elicitation": map[string]any{"url": map[string]any{}}},
		"clientInfo":   map[string]any{"name": "cli-e2e"}})
	_ = agent.post(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, false).Body.Close()
	target := filepath.Join(home, "from-afar.txt")
	resp := agent.post(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{
		"name": "write_file", "arguments": map[string]any{"path": target, "content": "approved from afar"}}}, true)
	events := sse(t, resp)
	el := nextEvent(t, events)
	_ = agent.post(map[string]any{"jsonrpc": "2.0", "id": el.ID, "result": map[string]any{"action": "accept"}}, false).Body.Close()

	rc, out = cli("approvals", "--gateway", origin)
	if rc != 0 || !strings.Contains(out, "fs/write_file") {
		t.Fatalf("list: %d %s", rc, out)
	}
	rc, out = cli("approvals", "approve", "a-", "--yes", "--gateway", origin)
	if rc != 0 || !strings.Contains(out, "approved a-") {
		t.Fatalf("approve: %d %s", rc, out)
	}
	var result msg
	for result.ID == nil || string(result.ID) != "2" {
		result = nextEvent(t, events)
	}
	if text, isErr := toolResult(t, result); isErr || !strings.HasPrefix(text, "wrote") {
		t.Fatalf("the call: %q %v", text, isErr)
	}
	if logs := e.gwLogs.String(); !strings.Contains(logs, `"via":"remote-cli"`) || !strings.Contains(logs, `"by":"u-approver"`) {
		t.Errorf("audit lacks via=remote-cli by=u-approver")
	}

	// Bearer tokens that are not a device-flow sign-in.
	page, _ := flow.idToken("u-approver", "approvals", nil)
	for name, tok := range map[string]string{
		"an agent's token":        provider.token(t, "u-approver", audience),
		"the page client's token": page,
	} {
		req, _ := http.NewRequest("GET", origin+"/approvals/api/v1/approvals", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, r.StatusCode)
		}
	}
}
