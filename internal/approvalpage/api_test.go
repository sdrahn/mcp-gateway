package approvalpage

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sdrahn/mcp-gateway/internal/broker"
)

// idToken is an ID token of the fake identity provider for aud.
func (f *fakeIdP) idToken(t *testing.T, sub, aud string, ttl time.Duration) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": f.srv.URL, "aud": aud, "sub": sub, "groups": []string{"ops"},
		"iat": time.Now().Unix(), "exp": time.Now().Add(ttl).Unix(),
	})
	tok.Header["kid"] = "k1"
	s, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func apiFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.page.DeviceClientID = "approvals-cli"
	return f
}

func (f *fixture) api(t *testing.T, method, path, token, body string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequest(method, f.srv.URL+"/approvals/api"+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func TestAPI(t *testing.T) {
	f := apiFixture(t)
	code, body, _ := f.api(t, "GET", "/v1/client", "", "")
	if code != 200 || !strings.Contains(body, `"client_id":"approvals-cli"`) || !strings.Contains(body, f.idp.srv.URL) {
		t.Fatalf("client: %d %s", code, body)
	}
	jack := f.idp.idToken(t, "jack", "approvals-cli", time.Hour)
	code, body, _ = f.api(t, "GET", "/v1/whoami", jack, "")
	if code != 200 || !strings.Contains(body, `"name":"jack"`) {
		t.Errorf("whoami: %d %s", code, body)
	}
	if len(f.audit.events) != 1 || !strings.HasPrefix(f.audit.events[0], "mcp-approver-sign-in ok jack") {
		t.Errorf("audit %v", f.audit.events)
	}
	code, body, _ = f.api(t, "GET", "/v1/approvals", jack, "")
	var list []broker.Pending
	if code != 200 || json.Unmarshal([]byte(body), &list) != nil || len(list) != 1 || list[0].ID != "a-1" {
		t.Fatalf("list: %d %s", code, body)
	}
	if code, _, _ = f.api(t, "GET", "/v1/approvals/a-1", jack, ""); code != 200 {
		t.Errorf("show: %d", code)
	}
	if code, body, _ = f.api(t, "POST", "/v1/approvals/a-1", jack, `{"decision":"approve","scope":"session"}`); code != 400 || !strings.Contains(body, "scope not offered") {
		t.Errorf("scope: %d %s", code, body)
	}
	if code, _, _ = f.api(t, "POST", "/v1/approvals/a-1", jack, `{"decision":"approve","scope":"1h"}`); code != 204 {
		t.Errorf("approve: %d", code)
	}
	if len(f.broker.resolved) != 1 || f.broker.resolved[0] != "a-1 approve 1h via remote-cli by jack" {
		t.Errorf("resolved %v", f.broker.resolved)
	}
	if code, _, _ = f.api(t, "GET", "/v1/grants", jack, ""); code != 200 {
		t.Errorf("grants: %d", code)
	}
	if code, _, _ = f.api(t, "DELETE", "/v1/grants/g-1", jack, ""); code != 204 || len(f.broker.revoked) != 1 || f.broker.revoked[0] != "g-1 via remote-cli" {
		t.Errorf("revoke: %d %v", code, f.broker.revoked)
	}

	// kim: signed in, may decide nothing.
	kim := f.idp.idToken(t, "kim", "approvals-cli", time.Hour)
	f.broker.pending["a-2"] = broker.Pending{ID: "a-2", Scopes: []string{"once"}}
	if code, body, _ = f.api(t, "GET", "/v1/approvals", kim, ""); code != 200 || strings.Contains(body, "a-2") {
		t.Errorf("kim's list: %d %s", code, body)
	}
	if code, _, _ = f.api(t, "POST", "/v1/approvals/a-2", kim, `{"decision":"approve","scope":"once"}`); code != 404 {
		t.Errorf("kim approves: %d", code)
	}
}

// Only the device client's ID tokens: not an agent's access token, not
// the page's, not an expired one, no cookie.
func TestAPIRefuses(t *testing.T) {
	f := apiFixture(t)
	for name, tok := range map[string]string{
		"no token":                   "",
		"an agent's access token":    f.idp.idToken(t, "jack", "https://gw.example.com/mcp", time.Hour),
		"the page client's ID token": f.idp.idToken(t, "jack", "approvals", time.Hour),
		"an expired one":             f.idp.idToken(t, "jack", "approvals-cli", -time.Hour),
		"garbage":                    "not.a.token",
	} {
		code, _, hdr := f.api(t, "GET", "/v1/approvals", tok, "")
		if code != 401 || !strings.HasPrefix(hdr.Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("%s: %d %v", name, code, hdr)
		}
	}
	// A browser signed in on the page: its cookie is no API sign-in.
	c := f.browser(t)
	if code, _, _ := get(t, c, f.srv.URL+"/approvals/"); code != 200 {
		t.Fatal(code)
	}
	if code, _, _ := get(t, c, f.srv.URL+"/approvals/api/v1/approvals"); code != 401 {
		t.Errorf("with the page's cookie: %d", code)
	}
	// Without a device client: no API.
	f.page.DeviceClientID = ""
	if code, _, _ := f.api(t, "GET", "/v1/client", "", ""); code != 404 {
		t.Errorf("no device client: %d", code)
	}
}

func TestAPIEvents(t *testing.T) {
	f := apiFixture(t)
	req, _ := http.NewRequest("GET", f.srv.URL+"/approvals/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+f.idp.idToken(t, "jack", "approvals-cli", 3*time.Second))
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	sc := bufio.NewScanner(resp.Body)
	next := func() string {
		for sc.Scan() {
			if d, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				return d
			}
		}
		return ""
	}
	if ev := next(); !strings.Contains(ev, `"type":"pending"`) || !strings.Contains(ev, `"id":"a-1"`) {
		t.Fatalf("first event %q", ev)
	}
	p := broker.Pending{ID: "a-3", Scopes: []string{"once"}}
	f.broker.announce(broker.Event{Type: "pending", ID: "a-3", New: true, Pending: &p})
	if ev := next(); !strings.Contains(ev, `"id":"a-3"`) || !strings.Contains(ev, `"url":"https://gw/approvals/a-3"`) {
		t.Errorf("new approval: %q", ev)
	}
	f.broker.announce(broker.Event{Type: "resolved", ID: "a-3"})
	if ev := next(); ev != `{"type":"resolved","id":"a-3"}` {
		t.Errorf("resolved: %q", ev)
	}
	// The stream ends when the token does (exp, plus a minute's leeway
	// the validator allows: not waited for here; the deadline is the
	// principal's Expires).
	_ = resp.Body.Close()
}
