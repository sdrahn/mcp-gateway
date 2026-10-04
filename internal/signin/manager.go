package signin

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/oauth"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
)

// Errors of the manager.
var (
	// ErrNotSignedIn means the principal has no (valid) token for the
	// server: they must sign in.
	ErrNotSignedIn = errors.New("not signed in")
	// ErrDeclined means the principal declined to open the sign-in link.
	ErrDeclined = errors.New("sign-in declined")
	// ErrTimeout means the sign-in did not complete in time.
	ErrTimeout = errors.New("sign-in timed out")
	// ErrTokenRejected means the server refused the access token an
	// instance started with; the next start refreshes it.
	ErrTokenRejected = errors.New("the server refused the access token")
)

// LinkError is the answer to a call that needs a sign-in, for a client
// that cannot open links (no URL elicitation): the principal opens URL,
// a link to the gateway valid until Expires, and calls again.
type LinkError struct {
	Server  string
	URL     string
	Expires time.Time
}

func (e *LinkError) Error() string {
	return fmt.Sprintf("sign in to %s with your account there to use its tools: open %s (valid until %s), then use the tool again",
		e.Server, e.URL, e.Expires.Format("15:04 MST"))
}

// RejectedMarker is in the error the connector answers with when the
// server refuses the access token (HTTP 401, mcp-http-connector -sign-in).
const RejectedMarker = "refused the access token"

const (
	// refreshBefore is how long before its expiry an access token is
	// refreshed when an instance starts.
	refreshBefore = 5 * time.Minute
	// metadataTTL is how long discovered metadata is used.
	metadataTTL = time.Hour
	// helperTimeout bounds one helper run.
	helperTimeout = 45 * time.Second
	// maxPending bounds the pending sign-ins (all principals).
	maxPending = 1000
)

// Manager runs principals' sign-ins to servers with sign_in.
type Manager struct {
	Store    *Store
	Launcher supervisor.Launcher
	Log      *slog.Logger
	Audit    *audit.Logger
	// RedirectURI is the callback URL (config.Gateway.RedirectURI).
	RedirectURI string
	// ClientMetadataURL is the URL of the client ID metadata document
	// the gateway serves ("" if it cannot be used as a client id).
	ClientMetadataURL string
	// RunDir holds the access tokens handed to instances, until their
	// units started (/run/mcp-gateway/credentials).
	RunDir string
	// Timeout bounds a sign-in (config.SignInSettings.Timeout).
	Timeout time.Duration
	// OnChange is called when a principal signed in to or out of a
	// server (the router tells their sessions, and stops their instances
	// on sign-out).
	OnChange func(k Key, server string, signedIn bool)
	// Now returns the time (tests).
	Now func() time.Time

	mu       sync.Mutex
	pending  map[string]*Pending // by state
	meta     map[string]*serverInfo
	refresh  map[string]*sync.Mutex // per server and principal
	helperID func() string
	wg       sync.WaitGroup // revocations in the background
}

// Pending is a sign-in waiting for its callback.
type Pending struct {
	State   string
	Server  string
	Key     Key
	URL     string // the authorization URL
	Expires time.Time

	verifier string
	backend  *config.Backend
	client   clientInfo
	info     *serverInfo
	done     chan error
	once     sync.Once
}

func (p *Pending) finish(err error) {
	p.once.Do(func() { p.done <- err; close(p.done) })
}

type serverInfo struct {
	resource oauth.ResourceMetadata
	server   oauth.ServerMetadata
	fetched  time.Time
}

type clientInfo struct {
	id, secret, secretCredential string
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.New(slog.DiscardHandler)
}

// List returns the sign-ins (without tokens).
func (m *Manager) List() []Entry { return m.Store.List() }

// Signed reports whether p has signed in to server.
func (m *Manager) Signed(p principal.Principal, server string) bool {
	_, _, ok, err := m.Store.Get(server, KeyOf(p))
	return ok && err == nil
}

// --- helper runs ---------------------------------------------------------

// helper runs one step of mcp-oauth-helper for server b, in a unit that
// may reach target's host (or b's proxy) only.
func (m *Manager) helper(ctx context.Context, b *config.Backend, p principal.Principal, target string, req oauth.Request) (oauth.Response, error) {
	if err := oauth.CheckURL(target); err != nil {
		return oauth.Response{}, err
	}
	req.URL = target
	hb := &config.Backend{
		Version: config.Version,
		// Its own unit names: mcp-<server>-sign-in-<id>.service.
		Name:         b.Name + "-sign-in",
		URL:          target,
		Proxy:        b.Proxy,
		ProxyHeaders: b.ProxyHeaders,
		Command:      []string{config.OAuthHelper},
		SELinuxType:  config.OAuthSELinuxType,
		Isolation:    config.IsolationSession,
		Network:      true,
		RunAs:        "dynamic",
		Discovery:    config.DiscoveryShared,
		Sandbox:      config.Sandbox{ProtectHome: "yes"},
	}
	if b.Proxy != "" {
		hb.Command = append(hb.Command, "-proxy", b.Proxy)
		for _, k := range slices.Sorted(maps.Keys(b.ProxyHeaders)) {
			hb.Command = append(hb.Command, "-proxy-header", k+": "+b.ProxyHeaders[k])
		}
	}
	// Only the credentials the helper needs: the client secret and those
	// of the proxy headers.
	creds, _ := b.ParseCredentials()
	for _, c := range creds {
		used := b.SignIn != nil && c.Name == b.SignIn.ClientSecret && req.ClientSecretCredential != ""
		for _, v := range b.ProxyHeaders {
			used = used || strings.Contains(v, "${CREDENTIAL:"+c.Name+"}")
		}
		if used {
			hb.Credentials = append(hb.Credentials, c.Name+":"+c.Path)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, helperTimeout)
	defer cancel()
	id := m.newHelperID()
	inst, err := m.Launcher.Start(ctx, hb, p, id)
	if err != nil {
		return oauth.Response{}, fmt.Errorf("starting the sign-in helper: %w", err)
	}
	defer func() { _ = inst.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = inst.Close() })
	defer stop()
	line, _ := json.Marshal(req)
	if _, err := inst.Write(append(line, '\n')); err != nil {
		return oauth.Response{}, fmt.Errorf("sign-in helper: %w", err)
	}
	out, err := bufio.NewReaderSize(inst, 64<<10).ReadBytes('\n')
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return oauth.Response{}, fmt.Errorf("sign-in helper: no answer: %w", err)
	}
	var resp oauth.Response
	if err := json.Unmarshal(out, &resp); err != nil {
		return oauth.Response{}, fmt.Errorf("sign-in helper: malformed answer: %w", err)
	}
	return resp, nil
}

func (m *Manager) newHelperID() string {
	if m.helperID != nil {
		return m.helperID()
	}
	return randomHex(8)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// discover returns the server's and its authorization server's metadata,
// cached for metadataTTL by server and url.
func (m *Manager) discover(ctx context.Context, b *config.Backend, p principal.Principal) (*serverInfo, error) {
	m.mu.Lock()
	if info := m.meta[metaKey(b)]; info != nil && m.now().Sub(info.fetched) < metadataTTL {
		m.mu.Unlock()
		return info, nil
	}
	m.mu.Unlock()
	r, err := m.helper(ctx, b, p, b.URL, oauth.Request{Op: oauth.OpResource})
	if err == nil {
		err = r.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("finding the authorization server of %s: %w", b.Name, err)
	}
	issuer := r.Resource.AuthorizationServers[0]
	s, err := m.helper(ctx, b, p, issuer, oauth.Request{Op: oauth.OpServer})
	if err == nil {
		err = s.Err()
	}
	if err == nil {
		err = s.Server.Check()
	}
	if err != nil {
		return nil, fmt.Errorf("reading the metadata of %s: %w", issuer, err)
	}
	info := &serverInfo{resource: *r.Resource, server: *s.Server, fetched: m.now()}
	m.mu.Lock()
	if m.meta == nil {
		m.meta = map[string]*serverInfo{}
	}
	m.meta[metaKey(b)] = info
	m.mu.Unlock()
	return info, nil
}

// metaKey is what discovered metadata is cached by: the server and its
// url (tokens of a previous url are revoked with that url's metadata).
func metaKey(b *config.Backend) string { return b.Name + "\x00" + b.URL }

// client returns the client the gateway is at the authorization server:
// the definition's, a client ID metadata document, or a registered one.
func (m *Manager) client(ctx context.Context, b *config.Backend, p principal.Principal, info *serverInfo) (clientInfo, error) {
	if b.SignIn.ClientID != "" {
		return clientInfo{id: b.SignIn.ClientID, secretCredential: b.SignIn.ClientSecret}, nil
	}
	if info.server.ClientIDMetadataDocumentSupported && strings.HasPrefix(m.ClientMetadataURL, "https://") {
		return clientInfo{id: m.ClientMetadataURL}, nil
	}
	if c, ok := m.Store.Client(b.Name, info.server.Issuer); ok {
		return clientInfo{id: c.ClientID, secret: c.ClientSecret}, nil
	}
	if info.server.RegistrationEndpoint == "" {
		return clientInfo{}, fmt.Errorf("server %s: the authorization server %s neither supports client ID metadata documents nor registration; register the gateway there (redirect URI %s) and set sign_in.client_id",
			b.Name, info.server.Issuer, m.RedirectURI)
	}
	r, err := m.helper(ctx, b, p, info.server.RegistrationEndpoint, oauth.Request{Op: oauth.OpRegister,
		RedirectURI: m.RedirectURI, ClientName: "mcp-gateway", Scope: m.scope(b, info)})
	if err == nil {
		err = r.Err()
	}
	if err != nil {
		return clientInfo{}, fmt.Errorf("registering at %s: %w", info.server.Issuer, err)
	}
	if err := m.Store.PutClient(b.Name, info.server.Issuer, *r.Client); err != nil {
		return clientInfo{}, err
	}
	m.log().Info("registered at the authorization server", "server", b.Name, "issuer", info.server.Issuer)
	return clientInfo{id: r.Client.ClientID, secret: r.Client.ClientSecret}, nil
}

func (m *Manager) scope(b *config.Backend, info *serverInfo) string {
	if len(b.SignIn.Scopes) > 0 {
		return strings.Join(b.SignIn.Scopes, " ")
	}
	return strings.Join(info.resource.ScopesSupported, " ")
}

// --- signing in ----------------------------------------------------------

// Begin starts a sign-in of p to server b and returns it; its URL is the
// link the principal opens.
func (m *Manager) Begin(ctx context.Context, b *config.Backend, p principal.Principal) (*Pending, error) {
	info, err := m.discover(ctx, b, p)
	if err != nil {
		return nil, err
	}
	c, err := m.client(ctx, b, p, info)
	if err != nil {
		return nil, err
	}
	pd := &Pending{State: oauth.NewState(), Server: b.Name, Key: KeyOf(p), Expires: m.now().Add(m.timeout()),
		verifier: oauth.NewVerifier(), backend: b, client: c, info: info, done: make(chan error, 1)}
	pd.URL, err = oauth.AuthURL(info.server.AuthorizationEndpoint, oauth.AuthParams{ClientID: c.id, RedirectURI: m.RedirectURI,
		Scope: m.scope(b, info), State: pd.State, Verifier: pd.verifier, Resource: b.URL})
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prune()
	if len(m.pending) >= maxPending {
		return nil, errors.New("too many sign-ins in progress")
	}
	if m.pending == nil {
		m.pending = map[string]*Pending{}
	}
	m.pending[pd.State] = pd
	m.Audit.Event("mcp-sign-in", true, map[string]string{"server": b.Name, "principal": p.Sub, "step": "started"})
	return pd, nil
}

func (m *Manager) timeout() time.Duration {
	if m.Timeout > 0 {
		return m.Timeout
	}
	return config.DefaultSignInTimeout
}

// prune ends expired pending sign-ins. Caller holds m.mu.
func (m *Manager) prune() {
	now := m.now()
	for st, pd := range m.pending {
		if now.After(pd.Expires) {
			delete(m.pending, st)
			pd.finish(ErrTimeout)
		}
	}
}

// take removes and returns the pending sign-in of state, if valid.
func (m *Manager) take(state string) *Pending {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prune()
	pd := m.pending[state]
	delete(m.pending, state)
	return pd
}

// pendingOf returns k's pending sign-in to server, if one is valid.
func (m *Manager) pendingOf(server string, k Key) *Pending {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prune()
	for _, pd := range m.pending {
		if pd.Server == server && pd.Key.Same(k) {
			return pd
		}
	}
	return nil
}

// pendingByState returns the pending sign-in of state, if valid, without
// taking it.
func (m *Manager) pendingByState(state string) *Pending {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prune()
	return m.pending[state]
}

// startURL is the link to the gateway that leads to pd's authorization
// URL (GET /oauth/start/{state}): short enough for an agent to show
// intact.
func (m *Manager) startURL(pd *Pending) string {
	return strings.TrimSuffix(m.RedirectURI, "/callback") + "/start/" + pd.State
}

// PendingInfo describes a pending sign-in to its principal.
type PendingInfo struct {
	Server  string    `json:"server"`
	URL     string    `json:"url"`
	Expires time.Time `json:"expires"`
}

// PendingFor returns the pending sign-ins of the principal whose local
// uid is uid (the control API's caller).
func (m *Manager) PendingFor(uid uint32) []PendingInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prune()
	var out []PendingInfo
	for _, pd := range m.pending {
		if pd.Key.UID != nil && *pd.Key.UID == uid {
			out = append(out, PendingInfo{Server: pd.Server, URL: pd.URL, Expires: pd.Expires})
		}
	}
	slices.SortFunc(out, func(a, b PendingInfo) int { return a.Expires.Compare(b.Expires) })
	return out
}

// Complete finishes the sign-in of state with the authorization server's
// answer on the callback: code, or an error.
func (m *Manager) Complete(ctx context.Context, state, code, errCode, errDesc string) (*Pending, error) {
	pd := m.take(state)
	if pd == nil {
		return nil, errors.New("this sign-in link is unknown, used or expired; start the sign-in again from your agent")
	}
	var err error
	switch {
	case errCode != "":
		err = &oauth.Error{Code: errCode, Description: errDesc}
	case code == "":
		err = errors.New("the authorization server sent no code")
	default:
		err = m.exchange(ctx, pd, code)
	}
	fields := map[string]string{"server": pd.Server, "principal": pd.Key.Sub, "step": "completed"}
	if err != nil {
		fields["step"], fields["reason"] = "failed", err.Error()
	}
	m.Audit.Event("mcp-sign-in", err == nil, fields)
	pd.finish(err)
	if err == nil && m.OnChange != nil {
		m.OnChange(pd.Key, pd.Server, true)
	}
	return pd, err
}

func (m *Manager) exchange(ctx context.Context, pd *Pending, code string) error {
	p := principal.Principal{Sub: pd.Key.Sub, Issuer: pd.Key.Issuer, UID: pd.Key.UID, Transport: pd.Key.Transport}
	r, err := m.helper(ctx, pd.backend, p, pd.info.server.TokenEndpoint, oauth.Request{Op: oauth.OpToken,
		GrantType: "authorization_code", Code: code, CodeVerifier: pd.verifier, RedirectURI: m.RedirectURI,
		Resource: pd.backend.URL, ClientID: pd.client.id, ClientSecret: pd.client.secret, ClientSecretCredential: pd.client.secretCredential})
	if err == nil {
		err = r.Err()
	}
	if err != nil {
		return fmt.Errorf("exchanging the code: %w", err)
	}
	t := r.Token
	if t.ExpiresIn > 0 {
		t.Expiry = m.now().Add(time.Duration(t.ExpiresIn) * time.Second)
	}
	return m.Store.Put(pd.Server, pd.backend.URL, pd.Key, t, m.now(), false)
}

// Wait waits for pd's callback, the sign-in's expiry or ctx.
func (m *Manager) Wait(ctx context.Context, pd *Pending) error {
	t := time.NewTimer(time.Until(pd.Expires))
	defer t.Stop()
	select {
	case err := <-pd.done:
		return err
	case <-t.C:
		if m.take(pd.State) != nil {
			pd.finish(ErrTimeout)
		}
		return ErrTimeout
	case <-ctx.Done():
		m.take(pd.State)
		return ctx.Err()
	}
}

// Run signs p in to server b through the client el: a URL elicitation of
// the sign-in link if the client takes those, else a message saying where
// to sign in (the link is shown to the principal only). It returns when
// the sign-in completed, failed or timed out.
func (m *Manager) Run(ctx context.Context, el broker.Elicitor, b *config.Backend, p principal.Principal) error {
	var pd *Pending
	if !el.SupportsURL() {
		pd = m.pendingOf(b.Name, KeyOf(p)) // asked again before signing in: the same link
	}
	if pd == nil {
		var err error
		if pd, err = m.Begin(ctx, b, p); err != nil {
			return err
		}
	}
	if !el.SupportsURL() {
		// The call ends at once with the link, which the agent shows; the
		// sign-in waits for its callback, and the next call goes on.
		le := &LinkError{Server: b.Name, URL: m.startURL(pd), Expires: pd.Expires}
		el.Notify("notifications/message", map[string]any{"level": "notice", "logger": "mcp-gateway", "data": "mcp-gateway: " + le.Error()})
		return le
	}
	defer el.Notify("notifications/elicitation/complete", map[string]any{"elicitationId": pd.State})
	type opened struct {
		res broker.ElicitResult
		err error
	}
	ch := make(chan opened, 1)
	ectx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		res, err := el.Elicit(ectx, broker.URLElicitParams{Mode: "url", ElicitationID: pd.State, URL: pd.URL,
			Message: fmt.Sprintf("Sign in to %s with your account there to use its tools. The gateway keeps the token; your agent never sees it.", b.Name)})
		ch <- opened{res, err}
	}()
	wait := make(chan error, 1)
	go func() { wait <- m.Wait(ectx, pd) }()
	for {
		select {
		case err := <-wait:
			return err
		case o := <-ch:
			if o.err != nil {
				m.take(pd.State)
				return fmt.Errorf("elicitation failed: %w", o.err)
			}
			if o.res.Action != "accept" {
				m.take(pd.State)
				m.Audit.Event("mcp-sign-in", false, map[string]string{"server": b.Name, "principal": p.Sub, "step": "failed", "reason": "declined"})
				return ErrDeclined
			}
			ch = nil // keep waiting for the callback
		}
	}
}

// --- tokens for instances ------------------------------------------------

// Prepare returns b as an instance of it for p is started: with the
// principal's access token as the credential sign-in (refreshed first if
// it expires within refreshBefore). The instance asks for a new token
// when the server refuses it (Token). cleanup removes the token file;
// call it once the unit started.
func (m *Manager) Prepare(ctx context.Context, b *config.Backend, p principal.Principal) (*config.Backend, func(), error) {
	k := KeyOf(p)
	lock := m.refreshLock(b.Name, k)
	lock.Lock()
	defer lock.Unlock()
	e, t, ok, err := m.Store.Get(b.Name, k)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, ErrNotSignedIn
	}
	if !e.Expiry.IsZero() && e.Expiry.Sub(m.now()) < refreshBefore {
		if e, t, err = m.refreshTokens(ctx, b, p, t); err != nil {
			return nil, nil, err
		}
	}
	dir := filepath.Join(m.RunDir, randomHex(16))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "access-token")
	if err := os.WriteFile(path, []byte(t.AccessToken), 0o600); err != nil {
		cleanup()
		return nil, nil, err
	}
	nb := *b
	nb.Credentials = append(slices.Clone(b.Credentials), config.SignInCredential+":"+path)
	return &nb, cleanup, nil
}

// Token returns p's access token for b and its expiry (zero if unknown),
// for a running instance whose server refused the token refused (HTTP
// 401): the token is refreshed if it is still refused, or expires within
// refreshBefore; one another instance refreshed meanwhile is returned as
// is. ErrNotSignedIn means p must sign in again.
func (m *Manager) Token(ctx context.Context, b *config.Backend, p principal.Principal, refused string) (string, time.Time, error) {
	k := KeyOf(p)
	lock := m.refreshLock(b.Name, k)
	lock.Lock()
	defer lock.Unlock()
	e, t, ok, err := m.Store.Get(b.Name, k)
	if err != nil {
		return "", time.Time{}, err
	}
	if !ok {
		return "", time.Time{}, ErrNotSignedIn
	}
	if t.AccessToken == refused || !e.Expiry.IsZero() && e.Expiry.Sub(m.now()) < refreshBefore {
		if e, t, err = m.refreshTokens(ctx, b, p, t); err != nil {
			return "", time.Time{}, err
		}
	}
	return t.AccessToken, e.Expiry, nil
}

func (m *Manager) refreshLock(server string, k Key) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.refresh == nil {
		m.refresh = map[string]*sync.Mutex{}
	}
	id := server + "\x00" + k.id()
	if m.refresh[id] == nil {
		m.refresh[id] = &sync.Mutex{}
	}
	return m.refresh[id]
}

// refreshTokens refreshes p's tokens for b. A refusal (invalid_grant)
// or no refresh token deletes them: the principal signs in again.
func (m *Manager) refreshTokens(ctx context.Context, b *config.Backend, p principal.Principal, t Tokens) (Entry, Tokens, error) {
	k := KeyOf(p)
	gone := func(reason string) (Entry, Tokens, error) {
		_, _, _ = m.Store.Delete(b.Name, k)
		m.Audit.Event("mcp-sign-in-refresh", false, map[string]string{"server": b.Name, "principal": p.Sub, "reason": reason, "tokens": "deleted"})
		if m.OnChange != nil {
			m.OnChange(k, b.Name, false)
		}
		return Entry{}, Tokens{}, ErrNotSignedIn
	}
	if t.RefreshToken == "" {
		return gone("the access token expired and there is no refresh token")
	}
	info, err := m.discover(ctx, b, p)
	if err != nil {
		return Entry{}, Tokens{}, err
	}
	c, err := m.client(ctx, b, p, info)
	if err != nil {
		return Entry{}, Tokens{}, err
	}
	r, err := m.helper(ctx, b, p, info.server.TokenEndpoint, oauth.Request{Op: oauth.OpToken, GrantType: "refresh_token",
		RefreshToken: t.RefreshToken, Resource: b.URL, ClientID: c.id, ClientSecret: c.secret, ClientSecretCredential: c.secretCredential})
	if err == nil {
		err = r.Err()
	}
	if oauth.IsInvalidGrant(err) {
		return gone(err.Error())
	}
	if err != nil {
		m.Audit.Event("mcp-sign-in-refresh", false, map[string]string{"server": b.Name, "principal": p.Sub, "reason": err.Error()})
		return Entry{}, Tokens{}, fmt.Errorf("refreshing the token for %s: %w", b.Name, err)
	}
	nt := r.Token
	if nt.ExpiresIn > 0 {
		nt.Expiry = m.now().Add(time.Duration(nt.ExpiresIn) * time.Second)
	}
	if err := m.Store.Put(b.Name, b.URL, k, nt, m.now(), true); err != nil {
		return Entry{}, Tokens{}, err
	}
	m.Audit.Event("mcp-sign-in-refresh", true, map[string]string{"server": b.Name, "principal": p.Sub})
	e, t2, _, err := m.Store.Get(b.Name, k)
	return e, t2, err
}

// Rejected records that server refused p's access token: the next
// instance refreshes it (or the principal signs in again).
func (m *Manager) Rejected(server string, p principal.Principal) {
	if err := m.Store.Expire(server, KeyOf(p), m.now()); err != nil {
		m.log().Warn("cannot mark the access token expired", "server", server, "err", err)
	}
}

// --- signing out ---------------------------------------------------------

// SignOut deletes k's tokens for server b, revokes them at the
// authorization server if it offers that, and reports whether there were
// any and whether they were revoked. by names who signed them out.
func (m *Manager) SignOut(ctx context.Context, b *config.Backend, k Key, by string) (found, revoked bool, err error) {
	t, ok, err := m.Store.Delete(b.Name, k)
	if err != nil || !ok {
		return ok, false, err
	}
	revoked = b.SignIn != nil && m.revokeLogged(ctx, b, k, t)
	m.Audit.Event("mcp-sign-out", true, map[string]string{"server": b.Name, "principal": k.Sub, "by": by, "revoked": yesNo(revoked)})
	if m.OnChange != nil {
		m.OnChange(k, b.Name, false)
	}
	return true, revoked, nil
}

// revokeLogged revokes k's tokens t for b, logging a failure, and reports
// whether the authorization server revoked them.
func (m *Manager) revokeLogged(ctx context.Context, b *config.Backend, k Key, t Tokens) bool {
	if err := m.revoke(ctx, b, k, t); err != nil {
		m.log().Warn("revoking the tokens failed", "server", b.Name, "principal", k.Sub, "err", err)
		return false
	}
	return true
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// --- tokens of a definition that changed ---------------------------------

// byGateway is who signs principals out when their tokens no longer fit
// the server's definition (the audit record's "by").
const byGateway = "mcp-gateway"

// obsolete says why the tokens kept for definition old do not fit next
// (nil: the server is gone), or "" if they do. Tokens are bound to the
// server's url (RFC 8707), so another url makes them useless.
func obsolete(old, next *config.Backend) string {
	switch {
	case old == nil || old.SignIn == nil:
		return ""
	case next == nil:
		return "the server's definition was removed"
	case next.SignIn == nil:
		return "the server's definition no longer has sign_in"
	case next.URL != old.URL:
		return "the server's url changed"
	}
	return ""
}

// DefinitionChanged is told that server old's definition was replaced by
// next (nil: removed). It drops the metadata cached for the server, and
// when the principals' tokens no longer fit (see obsolete), deletes them
// at once and revokes them at the authorization server in the
// background, with the old definition, auditing each as a sign-out by the
// gateway.
func (m *Manager) DefinitionChanged(old, next *config.Backend) {
	m.Forget(old.Name)
	if reason := obsolete(old, next); reason != "" {
		m.drop(old, reason, func(Entry) bool { return true })
	}
}

// Reconcile deletes the tokens kept for servers that no longer have
// sign_in in backends, or whose url changed, while the gateway was not
// running (at start). Tokens of another url are revoked with it; those of
// a server without a definition cannot be and are only deleted.
func (m *Manager) Reconcile(backends map[string]*config.Backend) {
	byServer := map[string]bool{}
	for _, e := range m.Store.List() {
		byServer[e.Server] = true
	}
	for server := range byServer {
		b := backends[server]
		switch {
		case b == nil:
			m.drop(&config.Backend{Name: server}, "the server's definition is gone", func(Entry) bool { return true })
		case b.SignIn == nil:
			m.drop(&config.Backend{Name: server}, "the server's definition no longer has sign_in", func(Entry) bool { return true })
		default:
			// Entries of 0.12 do not name their url: they are kept.
			urls := map[string]bool{}
			for _, e := range m.Store.List() {
				if e.Server == server && e.Resource != "" && e.Resource != b.URL {
					urls[e.Resource] = true
				}
			}
			for u := range urls {
				old := *b
				old.URL = u
				m.drop(&old, "the server's url changed", func(e Entry) bool { return e.Resource == u })
			}
		}
	}
}

// drop deletes the tokens of the entries of b's server that match, tells
// the router, and revokes them in the background when b has sign_in.
func (m *Manager) drop(b *config.Backend, reason string, match func(Entry) bool) {
	type gone struct {
		k Key
		t Tokens
	}
	var dropped []gone
	for _, e := range m.Store.List() {
		if e.Server != b.Name || !match(e) {
			continue
		}
		t, ok, err := m.Store.Delete(b.Name, e.Principal)
		if err != nil {
			m.log().Warn("cannot delete the tokens", "server", b.Name, "principal", e.Principal.Sub, "err", err)
			continue
		}
		if ok {
			dropped = append(dropped, gone{e.Principal, t})
			if m.OnChange != nil {
				m.OnChange(e.Principal, b.Name, false)
			}
		}
	}
	if len(dropped) == 0 {
		return
	}
	m.log().Info("sign-ins deleted", "server", b.Name, "reason", reason, "principals", len(dropped))
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		for _, g := range dropped {
			revoked := false
			if b.SignIn != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 2*helperTimeout)
				revoked = m.revokeLogged(ctx, b, g.k, g.t)
				cancel()
			}
			m.Audit.Event("mcp-sign-out", true, map[string]string{"server": b.Name, "principal": g.k.Sub, "by": byGateway,
				"reason": reason, "revoked": yesNo(revoked)})
		}
		// What revoking discovered is of the old definition.
		m.forget(metaKey(b))
	}()
}

// WaitRevocations waits for the revocations DefinitionChanged and Reconcile started
// (tests, shutdown).
func (m *Manager) WaitRevocations() { m.wg.Wait() }

func (m *Manager) revoke(ctx context.Context, b *config.Backend, k Key, t Tokens) error {
	p := principal.Principal{Sub: k.Sub, Issuer: k.Issuer, UID: k.UID, Transport: k.Transport}
	info, err := m.discover(ctx, b, p)
	if err != nil {
		return err
	}
	if info.server.RevocationEndpoint == "" {
		return errors.New("the authorization server offers no revocation")
	}
	c, err := m.client(ctx, b, p, info)
	if err != nil {
		return err
	}
	tok, hint := t.RefreshToken, "refresh_token"
	if tok == "" {
		tok, hint = t.AccessToken, "access_token"
	}
	r, err := m.helper(ctx, b, p, info.server.RevocationEndpoint, oauth.Request{Op: oauth.OpRevoke, Token: tok, TokenTypeHint: hint,
		ClientID: c.id, ClientSecret: c.secret, ClientSecretCredential: c.secretCredential})
	if err == nil {
		err = r.Err()
	}
	return err
}

// Forget drops what is cached about server (its definition changed or
// went away).
func (m *Manager) Forget(server string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key := range m.meta {
		if strings.HasPrefix(key, server+"\x00") {
			delete(m.meta, key)
		}
	}
}

// forget drops the metadata cached under key (metaKey).
func (m *Manager) forget(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.meta, key)
}
