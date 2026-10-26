package approvalpage

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sdrahn/mcp-gateway/internal/authn"
	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/pep"
)

// fakeIdP is an OpenID provider with the authorization code flow: the
// account that signs in is User; codes are bound to the PKCE challenge,
// the client and the redirect URI.
type fakeIdP struct {
	srv          *httptest.Server
	key          *rsa.PrivateKey
	clientID     string
	secret       string // "" : public client
	redirectURI  string
	mu           sync.Mutex
	user         string
	groups       []string
	codes        map[string]map[string]string
	badNonce     bool
	tokenCalls   int
	lastBasic    bool
	announceIss  bool
	omitIssParam bool
	// endSession offers an end_session_endpoint, which records the
	// sign-outs; prompts records the prompt of each authorization.
	endSession bool
	signOuts   []url.Values
	prompts    []string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, clientID: "approvals", user: "jack", groups: []string{"ops"}, codes: map[string]map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		md := map[string]any{
			"issuer": f.srv.URL, "jwks_uri": f.srv.URL + "/jwks",
			"authorization_endpoint": f.srv.URL + "/authorize", "token_endpoint": f.srv.URL + "/token",
			"code_challenge_methods_supported":               []string{"S256"},
			"authorization_response_iss_parameter_supported": f.announceIss,
		}
		if f.endSession {
			md["end_session_endpoint"] = f.srv.URL + "/logout"
		}
		_ = json.NewEncoder(w).Encode(md)
	})
	mux.HandleFunc("GET /logout", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f.mu.Lock()
		f.signOuts = append(f.signOuts, q)
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("post_logout_redirect_uri"), http.StatusFound)
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		enc := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "use": "sig", "n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != f.clientID || q.Get("redirect_uri") != f.redirectURI {
			http.Error(w, "unknown client or redirect_uri", http.StatusBadRequest)
			return
		}
		if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
			!strings.Contains(" "+q.Get("scope")+" ", " openid ") {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		code := randomToken()
		f.mu.Lock()
		f.prompts = append(f.prompts, q.Get("prompt"))
		f.codes[code] = map[string]string{"challenge": q.Get("code_challenge"), "nonce": q.Get("nonce"), "user": f.user}
		f.mu.Unlock()
		v := url.Values{"code": {code}, "state": {q.Get("state")}}
		if !f.omitIssParam {
			v.Set("iss", f.srv.URL)
		}
		http.Redirect(w, r, f.redirectURI+"?"+v.Encode(), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.tokenCalls++
		id, secret, basic := r.BasicAuth()
		f.lastBasic = basic
		if !basic {
			id = r.PostFormValue("client_id")
		}
		if id != f.clientID || secret != f.secret {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}
		c := f.codes[r.PostFormValue("code")]
		delete(f.codes, r.PostFormValue("code"))
		sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if c == nil || base64.RawURLEncoding.EncodeToString(sum[:]) != c["challenge"] || r.PostFormValue("redirect_uri") != f.redirectURI {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		nonce := c["nonce"]
		if f.badNonce {
			nonce = "other"
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": f.srv.URL, "aud": f.clientID, "sub": c["user"], "nonce": nonce, "groups": f.groups,
			"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		})
		tok.Header["kid"] = "k1"
		s, err := tok.SignedString(f.key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": s, "expires_in": 300})
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// fakeBroker: jack decides everything; others nothing.
type fakeBroker struct {
	mu       sync.Mutex
	pending  map[string]broker.Pending
	grants   []pep.Grant
	resolved []string
	revoked  []string
	seen     []broker.Approver
	subs     []chan broker.Event
}

func (b *fakeBroker) may(a broker.Approver) bool {
	b.mu.Lock()
	b.seen = append(b.seen, a)
	b.mu.Unlock()
	return a.Name == "jack"
}

func (b *fakeBroker) ListPending(_ context.Context, a broker.Approver) []broker.Pending {
	if !b.may(a) {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []broker.Pending
	for _, p := range b.pending {
		out = append(out, p)
	}
	return out
}

func (b *fakeBroker) GetPending(_ context.Context, a broker.Approver, id string) (broker.Pending, error) {
	b.mu.Lock()
	p, ok := b.pending[id]
	b.mu.Unlock()
	if !ok || !b.may(a) {
		return broker.Pending{}, broker.ErrNotFound
	}
	return p, nil
}

func (b *fakeBroker) ResolveVia(_ context.Context, a broker.Approver, id string, approve bool, scope, via string) (*pep.Grant, error) {
	b.mu.Lock()
	p, ok := b.pending[id]
	b.mu.Unlock()
	if !ok || !b.may(a) {
		return nil, broker.ErrNotFound
	}
	if approve && !contains(p.Scopes, scope) {
		return nil, broker.ErrBadScope
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.pending, id)
	b.resolved = append(b.resolved, id+" "+map[bool]string{true: "approve", false: "deny"}[approve]+" "+scope+" via "+via+" by "+a.Name)
	return nil, nil
}

func (b *fakeBroker) ListGrants(_ context.Context, a broker.Approver) []pep.Grant {
	if !b.may(a) {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]pep.Grant(nil), b.grants...)
}

func (b *fakeBroker) RevokeGrantVia(_ context.Context, a broker.Approver, id, via string) error {
	if !b.may(a) {
		return errors.New("no such grant")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revoked = append(b.revoked, id+" via "+via)
	return nil
}

func (b *fakeBroker) Subscribe() (<-chan broker.Event, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := make(chan broker.Event, 8)
	b.subs = append(b.subs, ch)
	return ch, func() {}
}

// announce sends an event to the subscribers.
func (b *fakeBroker) announce(ev broker.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs {
		ch <- ev
	}
}

func (b *fakeBroker) MayApprove(_ context.Context, a broker.Approver, _ broker.Pending) bool {
	return b.may(a)
}

func (b *fakeBroker) ApprovalURL(id string) string { return "https://gw/approvals/" + id }

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

type auditRec struct {
	mu     sync.Mutex
	events []string
}

func (a *auditRec) Event(op string, ok bool, f map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, op+" "+map[bool]string{true: "ok", false: "failed"}[ok]+" "+f["principal"]+" "+f["reason"])
}

type fixture struct {
	idp    *fakeIdP
	page   *Page
	srv    *httptest.Server
	broker *fakeBroker
	audit  *auditRec
	now    time.Time
}

func newFixture(t *testing.T, opts ...func(*Page)) *fixture {
	t.Helper()
	f := &fixture{idp: newFakeIdP(t), broker: &fakeBroker{pending: map[string]broker.Pending{
		"a-1": {ID: "a-1", Server: "fs", Name: "write_file", Action: "tools/call", Scopes: []string{"once", "1h"},
			Args: map[string]any{"path": "/home/ivy/notes.txt"}, Created: time.Now(), Expires: time.Now().Add(time.Minute)},
	}, grants: []pep.Grant{{ID: "g-1", Sub: "ivy", Server: "fs", Tool: "read_file", Scope: "duration"}}},
		audit: &auditRec{}, now: time.Now()}
	f.page = &Page{Issuer: f.idp.srv.URL, ClientID: "approvals", SessionTTL: time.Hour, Broker: f.broker,
		Tokens: authn.NewOAuth(config.HTTP{Issuer: f.idp.srv.URL, GroupsClaim: "groups"}, f.idp.srv.Client()),
		Client: f.idp.srv.Client(), Audit: f.audit, Scopes: []string{"profile"}}
	f.page.now = func() time.Time { return f.now }
	for _, o := range opts {
		o(f.page)
	}
	f.srv = httptest.NewTLSServer(f.page.Handler())
	t.Cleanup(f.srv.Close)
	f.page.Origin = f.srv.URL
	f.idp.redirectURI = f.page.RedirectURI()
	return f
}

// browser is a client with cookies that follows redirects.
func (f *fixture) browser(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := *f.srv.Client() // a copy: Client is shared
	c.Jar = jar
	return &c
}

// noRedirects is a client without cookies that shows redirects.
func (f *fixture) noRedirects() *http.Client {
	c := *f.srv.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

func get(t *testing.T, c *http.Client, u string) (int, string, http.Header) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func post(t *testing.T, c *http.Client, u string, form url.Values, hdr map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func csrfOf(t *testing.T, body string) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no CSRF token in %s", body)
	}
	return m[1]
}

func TestSignInAndDecide(t *testing.T) {
	f := newFixture(t)
	c := f.browser(t)
	code, body, hdr := get(t, c, f.srv.URL+"/approvals/a-1")
	if code != http.StatusOK || !strings.Contains(body, "fs/write_file") || !strings.Contains(body, "/home/ivy/notes.txt") ||
		!strings.Contains(body, "Signed in as <b>jack</b>") {
		t.Fatalf("after sign-in: %d %s", code, body)
	}
	if hdr.Get("X-Frame-Options") != "DENY" || !strings.Contains(hdr.Get("Content-Security-Policy"), "frame-ancestors 'none'") ||
		hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("headers %v", hdr)
	}
	// same-origin, not no-referrer: under no-referrer browsers send the
	// page's forms with "Origin: null", which the page refuses (1.9.0;
	// e2e's TestApprovalPageBrowser decides in a browser).
	if p := hdr.Get("Referrer-Policy"); p != "same-origin" {
		t.Errorf("Referrer-Policy %q", p)
	}
	if f.idp.lastBasic {
		t.Error("a public client authenticated with basic auth")
	}
	if len(f.audit.events) != 1 || !strings.HasPrefix(f.audit.events[0], "mcp-approver-sign-in ok jack") {
		t.Errorf("audit %v", f.audit.events)
	}
	a := f.broker.seen[len(f.broker.seen)-1]
	if !a.Remote || !a.NoUID || a.Root() || a.Name != "jack" || len(a.Groups) != 1 || a.Groups[0] != "ops" {
		t.Errorf("approver %+v", a)
	}
	csrf := csrfOf(t, body)

	// Refused: no CSRF token, another origin, another site.
	for name, try := range map[string]struct {
		form url.Values
		hdr  map[string]string
	}{
		"without the CSRF token": {url.Values{"decision": {"approve"}, "scope": {"once"}}, nil},
		"with a wrong token":     {url.Values{"decision": {"approve"}, "scope": {"once"}, "csrf": {"x" + csrf}}, nil},
		"from another origin":    {url.Values{"decision": {"approve"}, "scope": {"once"}, "csrf": {csrf}}, map[string]string{"Origin": "https://evil.example"}},
		"from another site":      {url.Values{"decision": {"approve"}, "scope": {"once"}, "csrf": {csrf}}, map[string]string{"Sec-Fetch-Site": "cross-site"}},
	} {
		if code, _ := post(t, c, f.srv.URL+"/approvals/a-1", try.form, try.hdr); code != http.StatusForbidden {
			t.Errorf("%s: %d, want 403", name, code)
		}
	}
	// Two Origin headers, the page's first: refused too.
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/approvals/a-1",
		strings.NewReader(url.Values{"decision": {"approve"}, "scope": {"once"}, "csrf": {csrf}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Origin", f.srv.URL)
	req.Header.Add("Origin", "https://evil.example")
	if resp, err := c.Do(req); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("two origins: %v %v", resp, err)
	} else {
		_ = resp.Body.Close()
	}
	if len(f.broker.resolved) != 0 {
		t.Fatalf("decided: %v", f.broker.resolved)
	}
	code, body = post(t, c, f.srv.URL+"/approvals/a-1", url.Values{"decision": {"approve"}, "scope": {"session"}, "csrf": {csrf}},
		map[string]string{"Origin": f.srv.URL})
	if code != http.StatusBadRequest || !strings.Contains(body, "does not offer the scope session") {
		t.Errorf("scope not offered: %d %s", code, body)
	}
	code, body = post(t, c, f.srv.URL+"/approvals/a-1", url.Values{"decision": {"approve"}, "scope": {"1h"}, "csrf": {csrf}},
		map[string]string{"Origin": f.srv.URL, "Sec-Fetch-Site": "same-origin"})
	if code != http.StatusOK || !strings.Contains(body, "Done: approved a-1 (scope 1h)") {
		t.Errorf("approve: %d %s", code, body)
	}
	if len(f.broker.resolved) != 1 || f.broker.resolved[0] != "a-1 approve 1h via page by jack" {
		t.Errorf("resolved %v", f.broker.resolved)
	}
	code, _ = post(t, c, f.srv.URL+"/approvals/a-1", url.Values{"decision": {"deny"}, "csrf": {csrf}}, nil)
	if code != http.StatusNotFound {
		t.Errorf("deciding again: %d, want 404", code)
	}

	// Grants: listed and revoked.
	_, body, _ = get(t, c, f.srv.URL+"/approvals/")
	if !strings.Contains(body, "fs/read_file") || !strings.Contains(body, "/approvals/grants/g-1/revoke") {
		t.Errorf("inbox: %s", body)
	}
	code, body = post(t, c, f.srv.URL+"/approvals/grants/g-1/revoke", url.Values{"csrf": {csrf}}, nil)
	if code != http.StatusOK || !strings.Contains(body, "revoked g-1") || len(f.broker.revoked) != 1 || f.broker.revoked[0] != "g-1 via page" {
		t.Errorf("revoke: %d %v", code, f.broker.revoked)
	}

	// Signing out ends the session: the next page asks to sign in again.
	if code, _ := post(t, c, f.srv.URL+"/approvals/logout", url.Values{"csrf": {csrf}}, nil); code != http.StatusOK {
		t.Errorf("logout: %d", code)
	}
	if code, _ := post(t, c, f.srv.URL+"/approvals/a-1", url.Values{"decision": {"deny"}, "csrf": {csrf}}, nil); code != http.StatusForbidden {
		t.Errorf("after logout: %d, want 403", code)
	}
}

func TestNotAnApprover(t *testing.T) {
	f := newFixture(t)
	f.idp.user = "kim"
	c := f.browser(t)
	_, body, _ := get(t, c, f.srv.URL+"/approvals/")
	if !strings.Contains(body, "No approvals wait for you") || strings.Contains(body, "write_file") {
		t.Errorf("inbox for kim: %s", body)
	}
	code, body, _ := get(t, c, f.srv.URL+"/approvals/a-1")
	if code != http.StatusNotFound {
		t.Errorf("kim opens a-1: %d", code)
	}
	if code, _ := post(t, c, f.srv.URL+"/approvals/a-1", url.Values{"decision": {"approve"}, "scope": {"once"}, "csrf": {csrfOf(t, body)}}, nil); code != http.StatusNotFound {
		t.Errorf("kim approves: %d, want 404", code)
	}
	if len(f.broker.resolved) != 0 {
		t.Errorf("resolved %v", f.broker.resolved)
	}
}

func TestBearerTokenIsNoSession(t *testing.T) {
	f := newFixture(t)
	c := f.noRedirects()
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/approvals/a-1", nil)
	req.Header.Set("Authorization", "Bearer some-agent-token")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), f.idp.srv.URL+"/authorize?") {
		t.Errorf("with a bearer token: %d %s, want the sign-in", resp.StatusCode, resp.Header.Get("Location"))
	}
	u, _ := url.Parse(resp.Header.Get("Location"))
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" || q.Get("scope") != "openid profile" ||
		q.Get("redirect_uri") != f.srv.URL+"/approvals/callback" {
		t.Errorf("authorization request %v", q)
	}
	req, _ = http.NewRequest(http.MethodPost, f.srv.URL+"/approvals/a-1", strings.NewReader("decision=approve&scope=once"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer some-agent-token")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || len(f.broker.resolved) != 0 {
		t.Errorf("POST with a bearer token: %d", resp.StatusCode)
	}
}

func TestSignInFailures(t *testing.T) {
	t.Run("unknown state", func(t *testing.T) {
		f := newFixture(t)
		code, body, _ := get(t, f.browser(t), f.srv.URL+"/approvals/callback?state=nope&code=x")
		if code != http.StatusBadRequest || !strings.Contains(body, "unknown, used or expired") {
			t.Errorf("%d %s", code, body)
		}
	})
	t.Run("another browser", func(t *testing.T) {
		f := newFixture(t)
		resp, err := f.noRedirects().Get(f.srv.URL + "/approvals/")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		// The attacker's sign-in link, opened in the victim's browser
		// (which lacks the login cookie): refused.
		code, body, _ := get(t, f.browser(t), resp.Header.Get("Location"))
		if code != http.StatusBadRequest || !strings.Contains(body, "started in another browser") {
			t.Errorf("%d %s", code, body)
		}
		if f.idp.tokenCalls != 0 {
			t.Error("the code was exchanged")
		}
	})
	t.Run("wrong nonce", func(t *testing.T) {
		f := newFixture(t)
		f.idp.badNonce = true
		code, body, _ := get(t, f.browser(t), f.srv.URL+"/approvals/")
		if code != http.StatusBadRequest || !strings.Contains(body, "nonce does not match") {
			t.Errorf("%d %s", code, body)
		}
		if len(f.audit.events) != 1 || !strings.HasPrefix(f.audit.events[0], "mcp-approver-sign-in failed") {
			t.Errorf("audit %v", f.audit.events)
		}
	})
	t.Run("issuer parameter announced but missing", func(t *testing.T) {
		f := newFixture(t)
		f.idp.announceIss, f.idp.omitIssParam = true, true
		code, body, _ := get(t, f.browser(t), f.srv.URL+"/approvals/")
		if code != http.StatusBadRequest || !strings.Contains(body, "names no issuer") {
			t.Errorf("%d %s", code, body)
		}
	})
	t.Run("confidential client with a wrong secret", func(t *testing.T) {
		f := newFixture(t)
		f.idp.secret = "s3cret"
		f.page.ClientSecret = "wrong"
		code, body, _ := get(t, f.browser(t), f.srv.URL+"/approvals/")
		if code != http.StatusBadRequest || !strings.Contains(body, "invalid_client") || !f.idp.lastBasic {
			t.Errorf("%d %s", code, body)
		}
		f.page.ClientSecret = "s3cret"
		if code, _, _ := get(t, f.browser(t), f.srv.URL+"/approvals/"); code != http.StatusOK {
			t.Errorf("with the secret: %d", code)
		}
	})
}

func TestSessionExpires(t *testing.T) {
	f := newFixture(t)
	c := f.browser(t)
	if code, _, _ := get(t, c, f.srv.URL+"/approvals/"); code != http.StatusOK {
		t.Fatal(code)
	}
	calls := f.idp.tokenCalls
	f.now = f.now.Add(2 * time.Hour)
	if code, _, _ := get(t, c, f.srv.URL+"/approvals/"); code != http.StatusOK || f.idp.tokenCalls != calls+1 {
		t.Errorf("after session_ttl: %d, signed in again: %v", code, f.idp.tokenCalls == calls+1)
	}
}

// Requests without a sign-in leave nothing on the gateway: however many
// start a sign-in, a browser's own still completes.
func TestSignInsInProgressCostNothing(t *testing.T) {
	f := newFixture(t)
	nr := f.noRedirects()
	for i := 0; i < 1500; i++ { // above the 1000 sign-ins in progress the page used to keep
		resp, err := nr.Get(f.srv.URL + "/approvals/")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("request %d: %d", i, resp.StatusCode)
		}
	}
	f.page.mu.Lock()
	n := len(f.page.sessions)
	f.page.mu.Unlock()
	if n != 0 {
		t.Errorf("%d sessions kept for requests without a sign-in", n)
	}
	if code, body, _ := get(t, f.browser(t), f.srv.URL+"/approvals/"); code != http.StatusOK || !strings.Contains(body, "Signed in as") {
		t.Errorf("sign-in after the flood: %d", code)
	}
}

func TestLoginCookie(t *testing.T) {
	f := newFixture(t)
	nr := f.noRedirects()
	start := func() (*http.Cookie, string) {
		resp, err := nr.Get(f.srv.URL + "/approvals/")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		u, _ := url.Parse(resp.Header.Get("Location"))
		for _, c := range resp.Cookies() {
			if c.Name == loginCookie {
				return c, u.Query().Get("state")
			}
		}
		t.Fatal("no login cookie")
		return nil, ""
	}
	callback := func(c *http.Cookie, state string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/approvals/callback?code=x&state="+url.QueryEscape(state), nil)
		req.AddCookie(c)
		resp, err := nr.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	mine, _ := start()
	_, theirs := start()
	// Another sign-in's answer (an attacker's, sent to this browser):
	// refused before the code is used.
	if code, body := callback(mine, theirs); code != http.StatusBadRequest || !strings.Contains(body, "for another sign-in") {
		t.Errorf("another sign-in's state: %d %s", code, body)
	}
	// A login cookie the page did not seal.
	forged := *mine
	forged.Value = mine.Value[:len(mine.Value)-4] + "AAAA"
	if code, body := callback(&forged, theirs); code != http.StatusBadRequest || !strings.Contains(body, "unknown, used or expired") {
		t.Errorf("forged cookie: %d %s", code, body)
	}
	// Expired.
	old, state := start()
	f.now = f.now.Add(loginTTL + time.Minute)
	if code, _ := callback(old, state); code != http.StatusBadRequest {
		t.Errorf("expired sign-in: %d", code)
	}
	if f.idp.tokenCalls != 0 {
		t.Errorf("%d code exchanges", f.idp.tokenCalls)
	}
}

// The inbox shows what the last decision did once, from the session:
// a link cannot make it show a decision.
func TestDoneIsNotFromTheURL(t *testing.T) {
	f := newFixture(t)
	c := f.browser(t)
	_, body, _ := get(t, c, f.srv.URL+"/approvals/?done=approved+everything")
	if strings.Contains(body, "approved everything") || strings.Contains(body, "Done:") {
		t.Errorf("done from the URL: %s", body)
	}
	_, body, _ = get(t, c, f.srv.URL+"/approvals/a-1")
	if code, body := post(t, c, f.srv.URL+"/approvals/a-1", url.Values{"decision": {"deny"}, "csrf": {csrfOf(t, body)}}, nil); code != http.StatusOK || !strings.Contains(body, "Done: denied a-1") {
		t.Errorf("deny: %d %s", code, body)
	}
	if _, body, _ = get(t, c, f.srv.URL+"/approvals/"); strings.Contains(body, "Done:") {
		t.Error("done shown twice")
	}
}

// Signing out ends the sign-in at the identity provider too (its
// end_session_endpoint, with the ID token as hint), and the next sign-in
// asks for the password again (prompt=login): else signing in again
// signed the approver in without asking. Without an end_session_endpoint
// the next sign-in still asks.
func TestSignOut(t *testing.T) {
	for _, endSession := range []bool{true, false} {
		f := newFixture(t)
		f.idp.endSession = endSession
		c := f.browser(t)
		_, body, _ := get(t, c, f.srv.URL+"/approvals/")
		csrf := csrfOf(t, body)
		code, body := post(t, c, f.srv.URL+"/approvals/logout", url.Values{"csrf": {csrf}}, nil)
		if endSession {
			if code != http.StatusOK || !strings.Contains(body, "signed out of the approval page and of the identity provider") {
				t.Errorf("signed out: %d %s", code, body)
			}
			if len(f.idp.signOuts) != 1 {
				t.Fatalf("sign-outs at the provider: %v", f.idp.signOuts)
			}
			q := f.idp.signOuts[0]
			if q.Get("client_id") != "approvals" || q.Get("post_logout_redirect_uri") != f.srv.URL+"/approvals/signed-out" ||
				strings.Count(q.Get("id_token_hint"), ".") != 2 {
				t.Errorf("sign-out request %v", q)
			}
		} else if code != http.StatusOK || !strings.Contains(body, "offers no sign-out") || len(f.idp.signOuts) != 0 {
			t.Errorf("signed out without end_session_endpoint: %d %s", code, body)
		}
		// The next sign-in asks again; the one after it does not.
		_, body, _ = get(t, c, f.srv.URL+"/approvals/")
		if !strings.Contains(body, "Signed in as") {
			t.Fatalf("signing in again: %s", body)
		}
		post(t, c, f.srv.URL+"/approvals/logout", url.Values{"csrf": {csrfOf(t, body)}}, nil)
		c2 := f.browser(t)
		get(t, c2, f.srv.URL+"/approvals/")
		if want := []string{"", "login", ""}; !slices.Equal(f.idp.prompts, want) {
			t.Errorf("end session %v: prompts %q, want %q", endSession, f.idp.prompts, want)
		}
	}
}
