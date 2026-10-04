package e2e

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/oauth/oauthtest"
)

// A server with sign_in, end to end: the gateway (exec supervisor) with
// its HTTP listener for the callback, the real mcp-http-connector and
// mcp-oauth-helper, and a fake server with its authorization server. A
// local client that takes URL elicitations signs in when it first calls
// a tool, and the call goes on as the account it signed in with.
func TestSignIn(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	as := &oauthtest.Server{AccountParam: "login"}
	asSrv := httptest.NewServer(as)
	t.Cleanup(asSrv.Close)
	as.Base = asSrv.URL

	dir := t.TempDir()
	provider := newIdP(t)
	certFile, keyFile, pool := selfSigned(t, dir)
	port := freePort(t)
	audience := fmt.Sprintf("https://127.0.0.1:%d/mcp", port)
	rbac := fmt.Sprintf(`{
	  "roles": {"ticketer": {"permissions": [{"server": "tickets", "tool": "whoami"}]}},
	  "bindings": {"groups": {}, "users": {%q: ["ticketer"]}}
	}`, me.Username)
	e := setup(t, rbac, nil, fmt.Sprintf(`http:
  listen: 127.0.0.1:%d
  cert_file: %s
  key_file: %s
  issuer: %s
  audience: %s
sign_in:
  timeout: 30s
`, port, certFile, keyFile, provider.srv.URL, audience))
	libexec := filepath.Join(e.tmp, "libexec", "mcp-gateway")
	build(t, libexec, "./cmd/mcp-http-connector")
	build(t, libexec, "./cmd/mcp-oauth-helper")
	// Added while the gateway runs: it reloads the definitions.
	writeFile(t, filepath.Join(e.tmp, "servers.d", "tickets.yaml"),
		fmt.Sprintf("name: tickets\nurl: %s\nsign_in: {}\n", as.Resource()))

	ctl := controlClient(e.ctlSock)
	deadline := time.Now().Add(15 * time.Second)
	for {
		var servers []struct {
			Name   string
			SignIn bool `json:"sign_in"`
		}
		controlDo(t, ctl, "GET", "/v1/servers", "", &servers)
		if len(servers) == 1 && servers[0].SignIn {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tickets not loaded:\n%s", e.gwLogs.String())
		}
		time.Sleep(200 * time.Millisecond)
	}

	c := newClient(t, e.connect, e.gwSock, "tickets")
	c.initialize(map[string]any{"elicitation": map[string]any{"url": map[string]any{}}})

	// Until alice signs in, the server offers only sign_in.
	c.request(10, "tools/list", map[string]any{})
	if got := listNames(t, readResponse(t, c, 10), "tools", "name"); got != "sign_in" {
		t.Fatalf("tools before signing in: %s", got)
	}

	// A call of whoami asks the client to open the sign-in page.
	browser := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	whoami := func(id int) msg {
		t.Helper()
		c.request(id, "tools/call", map[string]any{"name": "whoami", "arguments": map[string]any{}})
		var result msg
		for result.ID == nil {
			m := c.read()
			switch {
			case m.Method == "elicitation/create":
				var p struct{ Mode, URL, ElicitationID string }
				if err := json.Unmarshal(m.Params, &p); err != nil || p.Mode != "url" || !strings.HasPrefix(p.URL, as.Base+"/as/authorize?") {
					t.Fatalf("elicitation %s", m.Params)
				}
				c.send(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"action": "accept"}})
				// The browser: to the authorization server, and back to the
				// gateway's callback.
				resp, err := browser.Get(p.URL + "&login=alice")
				if err != nil {
					t.Fatal(err)
				}
				var page strings.Builder
				_, _ = fmt.Fprint(&page, resp.Status)
				b := make([]byte, 4096)
				n, _ := resp.Body.Read(b)
				_ = resp.Body.Close()
				if resp.StatusCode != 200 || !strings.Contains(string(b[:n]), "signed in to tickets") {
					t.Fatalf("callback: %s %s\n%s", page.String(), b[:n], e.gwLogs.String())
				}
			case m.Method != "":
				// notifications (list_changed, elicitation/complete)
			default:
				result = m
			}
		}
		return result
	}
	result := whoami(100)
	if text, isErr := toolResult(t, result); isErr || text != "signed in as alice" {
		t.Fatalf("whoami: %q %v\n%s", text, isErr, e.gwLogs.String())
	}
	// The access token expires at the server: the running instance gets
	// a refreshed one from the gateway and the call goes through, without
	// a new instance.
	as.ExpireAccessTokens()
	if text, isErr := toolResult(t, whoami(150)); isErr || text != "signed in as alice" || as.Refreshes() != 1 {
		t.Fatalf("after expiry: %q %v, refreshes %d\n%s", text, isErr, as.Refreshes(), e.gwLogs.String())
	}
	if n := strings.Count(e.gwLogs.String(), `msg="instance started" server=tickets`); n != 1 {
		t.Errorf("instances started: %d", n)
	}
	c.request(101, "tools/list", map[string]any{})
	if got := listNames(t, readResponse(t, c, 101), "tools", "name"); got != "whoami" {
		t.Errorf("tools after signing in: %s", got)
	}

	// The tokens are kept encrypted.
	data, err := os.ReadFile(filepath.Join(e.tmp, "state", "tokens", "tokens.json"))
	if err != nil || strings.Contains(string(data), "access_token") || !strings.Contains(string(data), `"sub": "`+me.Username+`"`) {
		t.Errorf("token store: %v\n%s", err, data)
	}

	// The control API lists the sign-in and signs out, revoking it.
	var list struct {
		SignIns []struct{ Server string } `json:"sign_ins"`
	}
	if code := controlDo(t, ctl, "GET", "/v1/sign-ins", "", &list); code != 200 || len(list.SignIns) != 1 || list.SignIns[0].Server != "tickets" {
		t.Fatalf("sign-ins: %d %+v", code, list)
	}
	var out struct {
		SignedOut int `json:"signed_out"`
		Revoked   int `json:"revoked"`
	}
	if code := controlDo(t, ctl, "DELETE", "/v1/sign-ins/tickets", "", &out); code != 200 || out.SignedOut != 1 || out.Revoked != 1 {
		t.Fatalf("sign out: %d %+v", code, out)
	}
	if len(as.Revoked()) != 1 {
		t.Errorf("revoked: %v", as.Revoked())
	}
	c.request(102, "tools/list", map[string]any{})
	if got := listNames(t, readResponse(t, c, 102), "tools", "name"); got != "sign_in" {
		t.Errorf("tools after signing out: %s", got)
	}
	for _, ev := range []string{`"event":"mcp-sign-in"`, `"event":"mcp-sign-out"`} {
		if !strings.Contains(e.gwLogs.String(), ev) {
			t.Errorf("no %s audit record", ev)
		}
	}

	// A client without URL elicitation gets a link to the gateway in the
	// tool's error; the browser follows it to the authorization server
	// and back, and the next call works.
	c2 := newClient(t, e.connect, e.gwSock, "tickets")
	c2.initialize(map[string]any{})
	c2.request(200, "tools/call", map[string]any{"name": "whoami", "arguments": map[string]any{}})
	text, isErr := toolResult(t, readResponse(t, c2, 200))
	link := regexp.MustCompile(`https://\S+/oauth/start/\S+`).FindString(text)
	if !isErr || link == "" || !strings.Contains(text, "sign in to tickets") {
		t.Fatalf("without URL elicitation: %q %v", text, isErr)
	}
	resp, err := browser.Get(link)
	if err != nil {
		t.Fatal(err)
	}
	page := make([]byte, 4096)
	n, _ := resp.Body.Read(page)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(page[:n]), "signed in to tickets for "+me.Username) {
		t.Fatalf("link: %s %s", resp.Status, page[:n])
	}
	c2.request(201, "tools/call", map[string]any{"name": "whoami", "arguments": map[string]any{}})
	if text, isErr := toolResult(t, readResponse(t, c2, 201)); isErr || text != "signed in as alice" {
		t.Fatalf("whoami after the link: %q %v", text, isErr)
	}

	// Signed in again, then the definition drops sign_in: the tokens go,
	// revoked at the authorization server.
	if text, isErr := toolResult(t, whoami(103)); isErr || text != "signed in as alice" {
		t.Fatalf("whoami again: %q %v", text, isErr)
	}
	writeFile(t, filepath.Join(e.tmp, "servers.d", "tickets.yaml"), fmt.Sprintf("name: tickets\nurl: %s\n", as.Resource()))
	deadline = time.Now().Add(15 * time.Second)
	for {
		list.SignIns = nil
		controlDo(t, ctl, "GET", "/v1/sign-ins", "", &list)
		if len(list.SignIns) == 0 && len(as.Revoked()) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after dropping sign_in: sign-ins %+v, revoked %v\n%s", list, as.Revoked(), e.gwLogs.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !strings.Contains(e.gwLogs.String(), `"by":"mcp-gateway"`) {
		t.Errorf("no sign-out by the gateway in the audit records")
	}
}

// readResponse reads messages until the response with id.
func readResponse(t *testing.T, c *client, id int) msg {
	t.Helper()
	want := fmt.Sprint(id)
	for {
		if m := c.read(); string(m.ID) == want {
			return m
		}
	}
}
