package signin

import (
	"bufio"
	"context"
	"encoding/json"
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
	if ok, err := f.m.SignOut(ctx, f.b, KeyOf(alice), "alice"); !ok || err != nil {
		t.Fatalf("sign out: %v %v", ok, err)
	}
	if len(f.as.Revoked()) != 1 || f.m.Signed(alice, "tickets") {
		t.Errorf("revoked %v", f.as.Revoked())
	}
	if _, _, err := f.m.Prepare(ctx, f.b, alice); err != ErrNotSignedIn {
		t.Errorf("after sign out: %v", err)
	}
}

func TestSignInDeclinedAndTimeout(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.m.Run(ctx, &fakeElicitor{url: true}, f.b, alice); err != ErrDeclined {
		t.Errorf("declined: %v", err)
	}
	// Without URL elicitation: a message, and the link for the principal.
	f.m.Timeout = 300 * time.Millisecond
	el := &fakeElicitor{}
	done := make(chan error, 1)
	go func() { done <- f.m.Run(ctx, el, f.b, alice) }()
	deadline := time.Now().Add(2 * time.Second)
	for len(f.m.PendingFor(1000)) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if p := f.m.PendingFor(1000); len(p) != 1 || p[0].Server != "tickets" || len(f.m.PendingFor(1001)) != 0 {
		t.Errorf("pending: %+v", p)
	}
	if err := <-done; err != ErrTimeout {
		t.Errorf("timeout: %v", err)
	}
	if el.notes[0] != "notifications/message" {
		t.Errorf("notes %v", el.notes)
	}
}

// A refused refresh deletes the tokens: the principal signs in again.
func TestRefreshRefused(t *testing.T) {
	f := newFixture(t)
	if err := f.m.Store.Put("tickets", KeyOf(alice), &oauth.Token{AccessToken: "old", RefreshToken: "unknown",
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
