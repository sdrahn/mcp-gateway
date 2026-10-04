package signin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/oauth"
	"github.com/sdrahn/mcp-gateway/internal/oauth/oauthtest"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
)

// helperLauncher runs the helper in process: each Start answers one
// request with oauth.Do, and records the units' definitions.
type helperLauncher struct {
	client *http.Client
	mu     sync.Mutex
	starts []*config.Backend
}

type pipeInstance struct{ net.Conn }

func (pipeInstance) Name() string { return "helper" }

func (l *helperLauncher) Start(_ context.Context, b *config.Backend, _ principal.Principal, _ string) (supervisor.Instance, error) {
	l.mu.Lock()
	l.starts = append(l.starts, b)
	l.mu.Unlock()
	gw, helper := net.Pipe()
	go func() {
		defer func() { _ = helper.Close() }()
		line, err := bufio.NewReader(helper).ReadBytes('\n')
		if err != nil {
			return
		}
		var req oauth.Request
		_ = json.Unmarshal(line, &req)
		out, _ := json.Marshal(oauth.Do(context.Background(), l.client, req, ""))
		_, _ = helper.Write(append(out, '\n'))
	}()
	return pipeInstance{gw}, nil
}

type fakeElicitor struct {
	url    bool
	accept bool
	opened chan string
	notes  []string
	mu     sync.Mutex
}

func (e *fakeElicitor) SupportsForm() bool { return false }
func (e *fakeElicitor) SupportsURL() bool  { return e.url }
func (e *fakeElicitor) Elicit(_ context.Context, p any) (broker.ElicitResult, error) {
	u := p.(broker.URLElicitParams)
	if !e.accept {
		return broker.ElicitResult{Action: "decline"}, nil
	}
	e.opened <- u.URL
	return broker.ElicitResult{Action: "accept"}, nil
}
func (e *fakeElicitor) Notify(method string, _ any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.notes = append(e.notes, method)
}

type fixture struct {
	as      *oauthtest.Server
	srv     *httptest.Server
	gw      *httptest.Server
	m       *Manager
	l       *helperLauncher
	b       *config.Backend
	changes []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{as: &oauthtest.Server{}}
	f.srv = httptest.NewServer(f.as)
	t.Cleanup(f.srv.Close)
	f.as.Base = f.srv.URL
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f.l = &helperLauncher{client: f.srv.Client()}
	f.m = &Manager{Store: st, Launcher: f.l, RunDir: t.TempDir(), Timeout: 5 * time.Second}
	f.gw = httptest.NewServer(f.m.Handler())
	t.Cleanup(f.gw.Close)
	f.m.RedirectURI = f.gw.URL + "/oauth/callback"
	f.m.OnChange = func(k Key, server string, in bool) {
		f.changes = append(f.changes, k.Sub+":"+server+":"+map[bool]string{true: "in", false: "out"}[in])
	}
	f.b = &config.Backend{Name: "tickets", URL: f.as.Resource(), SignIn: &config.SignIn{}}
	f.b.ApplyDefaults()
	return f
}

// browse follows the authorization URL like a browser: to the fake
// authorization server and its redirect to the gateway's callback.
func browse(t *testing.T, u string) (int, string) {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var b strings.Builder
	_, _ = bufio.NewReader(resp.Body).WriteTo(&b)
	return resp.StatusCode, b.String()
}

var alice = principal.Principal{Sub: "alice", UID: ptr(uint32(1000)), Transport: principal.TransportUnix}

func ptr[T any](v T) *T { return &v }

func TestSignInFlow(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	el := &fakeElicitor{url: true, accept: true, opened: make(chan string, 1)}
	done := make(chan error, 1)
	go func() { done <- f.m.Run(ctx, el, f.b, alice) }()
	var authURL string
	select {
	case authURL = <-el.opened:
	case err := <-done:
		t.Fatalf("Run ended early: %v", err)
	}
	u, _ := url.Parse(authURL)
	if q := u.Query(); q.Get("resource") != f.as.Resource() || q.Get("redirect_uri") != f.m.RedirectURI ||
		!strings.HasPrefix(q.Get("client_id"), "client-") || q.Get("scope") != "mcp.read" {
		t.Errorf("authorization URL %s", authURL)
	}
	if status, body := browse(t, authURL); status != 200 || !strings.Contains(body, "signed in to tickets") {
		t.Errorf("callback page: %d %s", status, body)
	}
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !f.m.Signed(alice, "tickets") || len(f.changes) != 1 || f.changes[0] != "alice:tickets:in" {
		t.Fatalf("signed: %v %v", f.m.Signed(alice, "tickets"), f.changes)
	}
	if !strings.Contains(strings.Join(el.notes, " "), "notifications/elicitation/complete") {
		t.Errorf("notifications %v", el.notes)
	}
	// The used link is refused.
	if status, body := browse(t, f.m.RedirectURI+"?state="+u.Query().Get("state")+"&code=x"); status != 400 || !strings.Contains(body, "unknown, used or expired") {
		t.Errorf("reused state: %d %s", status, body)
	}

	// Every helper unit may reach one host, in its own domain.
	for _, hb := range f.l.starts {
		if hb.SELinuxType != config.OAuthSELinuxType || hb.RunAs != "dynamic" || !strings.HasPrefix(hb.URL, f.srv.URL) {
			t.Errorf("helper unit %+v", hb)
		}
	}

	// An instance gets the access token as a credential, and a runtime
	// limit before its expiry.
	nb, cleanup, err := f.m.Prepare(ctx, f.b, alice)
	if err != nil {
		t.Fatal(err)
	}
	cred := nb.Credentials[len(nb.Credentials)-1]
	name, path, _ := strings.Cut(cred, ":")
	tok, _ := os.ReadFile(path)
	if name != config.SignInCredential || len(tok) == 0 || nb.RuntimeMax <= 50*time.Minute || nb.RuntimeMax > time.Hour {
		t.Errorf("prepared: %s %q %v", cred, tok, nb.RuntimeMax)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("token file left: %v", err)
	}

	// Near its expiry, the token is refreshed.
	f.m.Now = func() time.Time { return time.Now().Add(58 * time.Minute) }
	if _, cleanup, err = f.m.Prepare(ctx, f.b, alice); err != nil {
		t.Fatal(err)
	}
	cleanup()
	if f.as.Refreshes() != 1 {
		t.Errorf("refreshes: %d", f.as.Refreshes())
	}
	f.m.Now = nil

	// A token the server refused is refreshed at the next start.
	f.m.Rejected("tickets", alice)
	if _, cleanup, err = f.m.Prepare(ctx, f.b, alice); err != nil {
		t.Fatal(err)
	}
	cleanup()
	if f.as.Refreshes() != 2 {
		t.Errorf("refreshes after a refusal: %d", f.as.Refreshes())
	}

	// Signing out revokes the refresh token.
	if ok, revoked, err := f.m.SignOut(ctx, f.b, KeyOf(alice), "alice"); !ok || !revoked || err != nil {
		t.Fatalf("sign out: %v %v %v", ok, revoked, err)
	}
	if len(f.as.Revoked()) != 1 || f.m.Signed(alice, "tickets") {
		t.Errorf("revoked %v", f.as.Revoked())
	}
	if _, _, err := f.m.Prepare(ctx, f.b, alice); err != ErrNotSignedIn {
		t.Errorf("after sign out: %v", err)
	}
}

// signIn signs p in to f.b, as TestSignInFlow does.
func signIn(t *testing.T, f *fixture, p principal.Principal) {
	t.Helper()
	el := &fakeElicitor{url: true, accept: true, opened: make(chan string, 1)}
	done := make(chan error, 1)
	go func() { done <- f.m.Run(context.Background(), el, f.b, p) }()
	select {
	case u := <-el.opened:
		if status, body := browse(t, u); status != 200 {
			t.Fatalf("callback page: %d %s", status, body)
		}
	case err := <-done:
		t.Fatalf("Run ended early: %v", err)
	}
	if err := <-done; err != nil || !f.m.Signed(p, f.b.Name) {
		t.Fatalf("sign in: %v", err)
	}
}

// Tokens go with the definition they were for: removed, without sign_in,
// or with another url (they are bound to it), they are revoked and
// deleted; other changes keep them.
func TestDefinitionChanged(t *testing.T) {
	f := newFixture(t)
	signIn(t, f, alice)
	if e := f.m.Store.List(); len(e) != 1 || e[0].Resource != f.b.URL {
		t.Fatalf("entry %+v", e)
	}
	scopes := *f.b
	scopes.SignIn = &config.SignIn{Scopes: []string{"mcp.read"}}
	f.m.DefinitionChanged(f.b, &scopes)
	f.m.WaitRevocations()
	if !f.m.Signed(alice, "tickets") || len(f.as.Revoked()) != 0 {
		t.Fatalf("other scopes: signed %v, revoked %v", f.m.Signed(alice, "tickets"), f.as.Revoked())
	}

	moved := *f.b
	moved.URL = f.srv.URL + "/v2/mcp"
	f.m.DefinitionChanged(f.b, &moved)
	if f.m.Signed(alice, "tickets") || f.changes[len(f.changes)-1] != "alice:tickets:out" {
		t.Fatalf("other url: %v", f.changes)
	}
	f.m.WaitRevocations()
	if len(f.as.Revoked()) != 1 {
		t.Errorf("other url: revoked %v", f.as.Revoked())
	}

	signIn(t, f, alice)
	f.m.DefinitionChanged(f.b, nil)
	f.m.WaitRevocations()
	if f.m.Signed(alice, "tickets") || len(f.as.Revoked()) != 2 {
		t.Errorf("removed: revoked %v", f.as.Revoked())
	}

	signIn(t, f, alice)
	plain := *f.b
	plain.SignIn = nil
	f.m.DefinitionChanged(f.b, &plain)
	f.m.WaitRevocations()
	if f.m.Signed(alice, "tickets") || len(f.as.Revoked()) != 3 {
		t.Errorf("without sign_in: revoked %v", f.as.Revoked())
	}
}

// At start, tokens of servers that lost sign_in, went away or changed
// their url while the gateway was down go too.
func TestReconcile(t *testing.T) {
	f := newFixture(t)
	signIn(t, f, alice)
	f.m.Reconcile(map[string]*config.Backend{"tickets": f.b})
	f.m.WaitRevocations()
	if !f.m.Signed(alice, "tickets") {
		t.Fatal("same definition: signed out")
	}

	// Another url: revoked with the url the tokens were for.
	moved := *f.b
	moved.URL = f.srv.URL + "/v2/mcp"
	f.m.Reconcile(map[string]*config.Backend{"tickets": &moved})
	f.m.WaitRevocations()
	if f.m.Signed(alice, "tickets") || len(f.as.Revoked()) != 1 {
		t.Fatalf("other url: revoked %v", f.as.Revoked())
	}

	// No definition: nothing to revoke with, the tokens are deleted.
	signIn(t, f, alice)
	f.m.Reconcile(map[string]*config.Backend{})
	f.m.WaitRevocations()
	if f.m.Signed(alice, "tickets") || len(f.as.Revoked()) != 1 {
		t.Fatalf("no definition: revoked %v", f.as.Revoked())
	}

	// Entries of 0.12 do not name their url and are kept.
	if err := f.m.Store.Put("tickets", "", KeyOf(alice), &oauth.Token{AccessToken: "at"}, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	f.m.Reconcile(map[string]*config.Backend{"tickets": &moved})
	if !f.m.Signed(alice, "tickets") {
		t.Error("entry of 0.12: signed out")
	}
}

func TestSignInDeclinedLinkAndTimeout(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.m.Run(ctx, &fakeElicitor{url: true}, f.b, alice); err != ErrDeclined {
		t.Errorf("declined: %v", err)
	}
	// Without URL elicitation the call ends at once with a link to the
	// gateway, which the agent shows; the link leads to the authorization
	// server while the sign-in waits.
	el := &fakeElicitor{}
	err := f.m.Run(ctx, el, f.b, alice)
	var le *LinkError
	if !errors.As(err, &le) || le.Server != "tickets" || !strings.HasPrefix(le.URL, f.gw.URL+"/oauth/start/") ||
		!strings.Contains(err.Error(), le.URL) {
		t.Fatalf("without URL elicitation: %v", err)
	}
	if len(el.notes) != 1 || el.notes[0] != "notifications/message" {
		t.Errorf("notes %v", el.notes)
	}
	if p := f.m.PendingFor(1000); len(p) != 1 || p[0].Server != "tickets" || len(f.m.PendingFor(1001)) != 0 {
		t.Errorf("pending: %+v", p)
	}
	// Asked again before signing in: the same link.
	var again *LinkError
	if err := f.m.Run(ctx, el, f.b, alice); !errors.As(err, &again) || again.URL != le.URL {
		t.Errorf("again: %v", err)
	}
	// Opening the link (twice: a chat program may preview it) signs in.
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noFollow.Get(le.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), f.as.Issuer()+"/authorize?") {
		t.Fatalf("link: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if status, body := browse(t, le.URL); status != 200 || !strings.Contains(body, "signed in to tickets for alice") {
		t.Fatalf("callback: %d %s", status, body)
	}
	if !f.m.Signed(alice, "tickets") {
		t.Error("not signed in")
	}
	// The link is used up.
	if status, body := browse(t, le.URL); status != 404 || !strings.Contains(body, "unknown, used or expired") {
		t.Errorf("used link: %d %s", status, body)
	}

	// An expired sign-in.
	f.m.Timeout = 50 * time.Millisecond
	pd, err := f.m.Begin(ctx, f.b, alice)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := f.m.Wait(ctx, pd); err != ErrTimeout {
		t.Errorf("timeout: %v", err)
	}
}

// A refused refresh deletes the tokens: the principal signs in again.
func TestRefreshRefused(t *testing.T) {
	f := newFixture(t)
	if err := f.m.Store.Put("tickets", f.b.URL, KeyOf(alice), &oauth.Token{AccessToken: "old", RefreshToken: "unknown",
		Expiry: time.Now().Add(time.Minute)}, time.Now(), false); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.m.Prepare(context.Background(), f.b, alice); err != ErrNotSignedIn {
		t.Errorf("prepare: %v", err)
	}
	if f.m.Signed(alice, "tickets") || len(f.changes) != 1 || f.changes[0] != "alice:tickets:out" {
		t.Errorf("after refusal: %v", f.changes)
	}
}

func TestClientChoice(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// A client ID metadata document where supported.
	f.as.CIMD = true
	f.m.ClientMetadataURL = "https://gw.example.com/oauth/client.json"
	pd, err := f.m.Begin(ctx, f.b, alice)
	if err != nil || pd.client.id != f.m.ClientMetadataURL {
		t.Fatalf("CIMD: %+v %v", pd, err)
	}
	// Neither: an error naming client_id.
	f.m.Forget("tickets")
	f.as.CIMD, f.as.NoRegistration = false, true
	if _, err := f.m.Begin(ctx, f.b, alice); err == nil || !strings.Contains(err.Error(), "sign_in.client_id") {
		t.Errorf("no client: %v", err)
	}
	// The definition's client.
	f.b.SignIn.ClientID = "registered"
	if pd, err := f.m.Begin(ctx, f.b, alice); err != nil || pd.client.id != "registered" {
		t.Errorf("client_id: %v", err)
	}

	// The client ID metadata document.
	resp, err := http.Get(f.gw.URL + "/oauth/client.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	_ = resp.Body.Close()
	if doc["client_id"] != f.m.ClientMetadataURL || doc["token_endpoint_auth_method"] != "none" {
		t.Errorf("client.json %v", doc)
	}
}
