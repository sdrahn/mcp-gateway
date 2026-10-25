// Package approvalpage is the gateway's own approval page on its HTTP
// listener (docs/architecture.md, section 11, step 39 stage C; D21):
// /approvals/ lists the approvals the signed-in approver may decide and
// the grants they may revoke, /approvals/{id} shows one approval to
// approve or deny. Approvers sign in with the identity provider the
// gateway validates tokens from (OpenID Connect, authorization code with
// PKCE, as the client approvals.page names); the page keeps the sign-in
// as a session cookie of its own and never takes an agent's token. The
// approver rules, scopes and audit are the broker's, as for Cockpit and
// the command line; decisions are audited with via=page.
package approvalpage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/oauth"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Broker is what the page decides with (broker.Broker).
type Broker interface {
	ListPending(ctx context.Context, a broker.Approver) []broker.Pending
	GetPending(ctx context.Context, a broker.Approver, id string) (broker.Pending, error)
	ResolveVia(ctx context.Context, a broker.Approver, id string, approve bool, scope, via string) (*pep.Grant, error)
	ListGrants(ctx context.Context, a broker.Approver) []pep.Grant
	RevokeGrantVia(ctx context.Context, a broker.Approver, id, via string) error
	// For the API's events.
	Subscribe() (<-chan broker.Event, func())
	MayApprove(ctx context.Context, a broker.Approver, p broker.Pending) bool
	ApprovalURL(id string) string
}

// IDTokens validates the identity provider's ID tokens (authn.OAuth).
type IDTokens interface {
	IDToken(ctx context.Context, raw, clientID, nonce string) (principal.Principal, error)
	ApproverToken(ctx context.Context, raw, clientID string) (principal.Principal, error)
}

// Auditor records sign-ins on the page (audit.Logger).
type Auditor interface {
	Event(op string, ok bool, fields map[string]string)
}

const (
	// Via is how the page's decisions are audited.
	Via = "page"
	// sessionCookie holds the sign-in; loginCookie holds a sign-in in
	// progress, sealed: the page keeps nothing for a browser that has
	// not signed in, so requests without a sign-in cannot crowd out
	// others'. __Host-: Secure, Path=/, no Domain, so no other host can
	// set them.
	sessionCookie = "__Host-mcpgw-approvals"
	loginCookie   = "__Host-mcpgw-approvals-login"
	// loginTTL bounds a sign-in in progress; maxSessions bounds the
	// sign-ins the page keeps (made only after the identity provider
	// signed someone in).
	loginTTL    = 10 * time.Minute
	maxSessions = 10000
	metaMaxAge  = time.Hour
	// exchangeTimeout bounds the code exchange.
	exchangeTimeout = 30 * time.Second
)

// Page is the approval page. Set the fields, then serve Handler.
type Page struct {
	// Issuer is http.issuer; Origin the origin of http.audience, where
	// the page is served (https://gw.example.com:8443).
	Issuer, Origin string
	// ClientID and ClientSecret are the gateway's client at the identity
	// provider (no secret: a public client).
	ClientID, ClientSecret string
	// Scopes are asked for besides openid.
	Scopes []string
	// DeviceClientID is the client the command line signs in as with the
	// device flow, whose ID tokens the approval API takes (api.go);
	// empty: no API.
	DeviceClientID string
	SessionTTL     time.Duration
	Broker         Broker
	Tokens         IDTokens
	// Client reaches the identity provider (discovery, token endpoint).
	Client *http.Client
	Audit  Auditor
	Log    *slog.Logger

	now func() time.Time

	// sealer seals the login cookie, with a key made at start: a
	// restart ends the sign-ins in progress.
	sealer cipher.AEAD

	mu       sync.Mutex
	sessions map[string]*session // by the hash of the cookie
	meta     *metadata
	metaAt   time.Time
}

// login is a sign-in in progress, as the login cookie holds it.
type login struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"x"`
	Created  int64  `json:"t"`
}

type session struct {
	Approver broker.Approver
	CSRF     string
	expires  time.Time
	// done is what the last decision did, shown once on the inbox.
	done string
}

// loginAAD binds a sealed login to its cookie.
var loginAAD = []byte(loginCookie)

// seal makes the login cookie's value: nonce and AES-GCM ciphertext.
func (pg *Page) seal(l login) string {
	plain, _ := json.Marshal(l)
	nonce := make([]byte, pg.sealer.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(pg.sealer.Seal(nonce, nonce, plain, loginAAD))
}

// open returns the login of a cookie value the page sealed.
func (pg *Page) open(v string) (login, bool) {
	var l login
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil || len(b) < pg.sealer.NonceSize() {
		return l, false
	}
	n := pg.sealer.NonceSize()
	plain, err := pg.sealer.Open(nil, b[:n], b[n:], loginAAD)
	if err != nil || json.Unmarshal(plain, &l) != nil {
		return l, false
	}
	return l, true
}

// metadata is what the page uses of the identity provider's discovery
// document.
type metadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
	IssParameter          bool     `json:"authorization_response_iss_parameter_supported"`
}

// RedirectURI is where the identity provider sends approvers back.
func (pg *Page) RedirectURI() string { return pg.Origin + "/approvals/callback" }

// Handler serves /approvals/.
func (pg *Page) Handler() http.Handler {
	if pg.now == nil {
		pg.now = time.Now
	}
	if pg.Log == nil {
		pg.Log = slog.New(slog.DiscardHandler)
	}
	if pg.Client == nil {
		pg.Client = &http.Client{Timeout: exchangeTimeout}
	}
	if pg.sealer == nil {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			panic(err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		if pg.sealer, err = cipher.NewGCM(block); err != nil {
			panic(err)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /approvals/{$}", pg.inbox)
	mux.HandleFunc("GET /approvals/callback", pg.callback)
	mux.HandleFunc("POST /approvals/logout", pg.logout)
	mux.HandleFunc("GET /approvals/{id}", pg.show)
	mux.HandleFunc("POST /approvals/{id}", pg.decide)
	mux.HandleFunc("POST /approvals/grants/{id}/revoke", pg.revoke)
	pg.apiRoutes(mux)
	mux.HandleFunc("/approvals/", func(w http.ResponseWriter, r *http.Request) {
		pg.page(w, http.StatusNotFound, "Not found", "There is no such page.", nil)
	})
	return headers(mux)
}

// headers sets what every answer of the page carries: nothing of it is
// framed (clickjacking), cached or sent on as a referrer, and it loads
// nothing but its own inline style.
func headers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

// current returns the request's session, if its cookie names a live one.
// Only the cookie counts: an Authorization header (an agent's token) is
// never a sign-in on the page.
func (pg *Page) current(r *http.Request) *session {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	key := hashKey(c.Value)
	pg.mu.Lock()
	defer pg.mu.Unlock()
	s := pg.sessions[key]
	if s == nil {
		return nil
	}
	if !pg.now().Before(s.expires) {
		delete(pg.sessions, key)
		return nil
	}
	return s
}

// signedIn returns the session of a GET request, or starts signing in
// (and returns nil) when there is none.
func (pg *Page) signedIn(w http.ResponseWriter, r *http.Request) *session {
	if s := pg.current(r); s != nil {
		return s
	}
	pg.startLogin(w, r, r.URL.Path)
	return nil
}

// startLogin sends the browser to the identity provider's authorization
// endpoint, to come back to next (a path of the page).
func (pg *Page) startLogin(w http.ResponseWriter, r *http.Request, next string) {
	md, err := pg.metadata(r.Context())
	if err != nil {
		pg.Log.Warn("approval page: identity provider", "err", err)
		pg.page(w, http.StatusBadGateway, "Sign-in unavailable",
			"The gateway cannot reach its identity provider: "+err.Error(), nil)
		return
	}
	if !strings.HasPrefix(next, "/approvals/") || strings.HasPrefix(next, "/approvals/callback") {
		next = "/approvals/"
	}
	l := login{State: oauth.NewState(), Nonce: oauth.NewState(), Verifier: oauth.NewVerifier(), Next: next, Created: pg.now().Unix()}

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {pg.ClientID},
		"redirect_uri":          {pg.RedirectURI()},
		"scope":                 {strings.Join(append([]string{"openid"}, pg.scopes()...), " ")},
		"state":                 {l.State},
		"nonce":                 {l.Nonce},
		"code_challenge":        {oauth.Challenge(l.Verifier)},
		"code_challenge_method": {"S256"},
	}
	target := md.AuthorizationEndpoint
	if strings.Contains(target, "?") {
		target += "&" + q.Encode()
	} else {
		target += "?" + q.Encode()
	}
	http.SetCookie(w, &http.Cookie{Name: loginCookie, Value: pg.seal(l), Path: "/", MaxAge: int(loginTTL / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, target, http.StatusFound)
}

func (pg *Page) scopes() []string {
	var out []string
	for _, s := range pg.Scopes {
		if s != "openid" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// callback completes a sign-in: the browser's login cookie holds the
// sign-in in progress, whose state the answer must name (a sign-in
// started in another browser, or a login cookie of another, does not
// match); the code is exchanged with the PKCE verifier; the ID token
// must carry the nonce.
func (pg *Page) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	http.SetCookie(w, &http.Cookie{Name: loginCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	again := "Open the approval page again to sign in."
	var l login
	ok := false
	if c, err := r.Cookie(loginCookie); err == nil {
		l, ok = pg.open(c.Value)
	}
	if !ok || pg.now().Sub(time.Unix(l.Created, 0)) > loginTTL {
		pg.page(w, http.StatusBadRequest, "Sign-in failed", "This sign-in is unknown, used or expired, or was started in another browser. "+again, nil)
		return
	}
	if q.Get("state") == "" || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(l.State)) != 1 {
		pg.failed(w, "", "the answer is for another sign-in than this browser's (started in another browser?)", again)
		return
	}
	md, err := pg.metadata(r.Context())
	if err != nil {
		pg.failed(w, "", err.Error(), again)
		return
	}
	// RFC 9207: an iss parameter must name the issuer; one the provider
	// announces must be there (a mix-up of providers otherwise).
	if iss, ok := q["iss"]; ok && iss[0] != md.Issuer {
		pg.failed(w, "", fmt.Sprintf("the answer names the issuer %q, not %q", iss[0], md.Issuer), again)
		return
	} else if !ok && md.IssParameter {
		pg.failed(w, "", "the answer names no issuer, which the identity provider announces", again)
		return
	}
	if e := q.Get("error"); e != "" {
		msg := e
		if d := q.Get("error_description"); d != "" {
			msg += ": " + d
		}
		pg.failed(w, "", "the identity provider refused: "+msg, again)
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), exchangeTimeout)
	defer cancel()
	idToken, err := pg.exchange(ctx, md.TokenEndpoint, q.Get("code"), l.Verifier)
	if err != nil {
		pg.failed(w, "", err.Error(), again)
		return
	}
	p, err := pg.Tokens.IDToken(ctx, idToken, pg.ClientID, l.Nonce)
	if err != nil {
		pg.failed(w, "", "the ID token is not valid: "+err.Error(), again)
		return
	}
	a := approverOf(p)
	value := randomToken()
	s := &session{Approver: a, CSRF: randomToken(), expires: pg.now().Add(pg.SessionTTL)}
	pg.mu.Lock()
	if pg.sessions == nil {
		pg.sessions = map[string]*session{}
	}
	now := pg.now()
	for k, old := range pg.sessions {
		if !now.Before(old.expires) {
			delete(pg.sessions, k)
		}
	}
	full := len(pg.sessions) >= maxSessions
	if !full {
		pg.sessions[hashKey(value)] = s
	}
	pg.mu.Unlock()
	if full {
		pg.failed(w, a.Name, "too many sign-ins", "Try again later.")
		return
	}
	pg.audit(true, a.Name, "")
	pg.Log.Info("approval page: signed in", "sub", a.Name, "local", !a.NoUID)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: value, Path: "/", MaxAge: int(pg.SessionTTL / time.Second),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, l.Next, http.StatusSeeOther)
}

// approverOf is the approver a sign-in makes: the principal's subject
// (its local account, when the token maps to one) and groups. Never root,
// whatever account it maps to.
func approverOf(p principal.Principal) broker.Approver {
	a := broker.Approver{Name: p.Sub, Groups: p.Groups, Remote: true, Issuer: p.Issuer}
	if p.UID != nil {
		a.UID = *p.UID
	} else {
		a.NoUID = true
	}
	return a
}

// failed shows why a sign-in failed and audits it.
func (pg *Page) failed(w http.ResponseWriter, sub, reason, hint string) {
	pg.audit(false, sub, reason)
	pg.Log.Warn("approval page: sign-in failed", "sub", sub, "reason", reason)
	pg.page(w, http.StatusBadRequest, "Sign-in failed", "Signing in failed: "+reason+". "+hint, nil)
}

func (pg *Page) audit(ok bool, sub, reason string, via ...string) {
	if pg.Audit == nil {
		return
	}
	v := Via
	if len(via) > 0 {
		v = via[0]
	}
	f := map[string]string{"principal": sub, "issuer": pg.Issuer, "via": v}
	if reason != "" {
		f["reason"] = reason
	}
	pg.Audit.Event("mcp-approver-sign-in", ok, f)
}

// exchange trades the authorization code for tokens and returns the ID
// token.
func (pg *Page) exchange(ctx context.Context, endpoint, code, verifier string) (string, error) {
	if code == "" {
		return "", errors.New("the answer carries no code")
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {pg.RedirectURI()},
		"code_verifier": {verifier},
	}
	if pg.ClientSecret == "" {
		form.Set("client_id", pg.ClientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if pg.ClientSecret != "" {
		// RFC 6749, section 2.3.1: both form-urlencoded first.
		req.SetBasicAuth(url.QueryEscape(pg.ClientID), url.QueryEscape(pg.ClientSecret))
	}
	resp, err := pg.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		IDToken          string `json:"id_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", fmt.Errorf("token endpoint: %s, %v", resp.Status, err)
	}
	if body.Error != "" {
		msg := body.Error
		if body.ErrorDescription != "" {
			msg += ": " + body.ErrorDescription
		}
		return "", errors.New("token endpoint: " + msg)
	}
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("token endpoint: " + resp.Status)
	}
	if body.IDToken == "" {
		return "", errors.New("token endpoint: no id_token (is openid among the client's scopes?)")
	}
	return body.IDToken, nil
}

// metadata returns the identity provider's discovery document, fetched
// at most once an hour.
func (pg *Page) metadata(ctx context.Context) (*metadata, error) {
	pg.mu.Lock()
	md, at := pg.meta, pg.metaAt
	pg.mu.Unlock()
	if md != nil && pg.now().Sub(at) < metaMaxAge {
		return md, nil
	}
	u := strings.TrimSuffix(pg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := pg.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery: GET %s: %s", u, resp.Status)
	}
	md = &metadata{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(md); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	switch {
	case md.Issuer != pg.Issuer:
		return nil, fmt.Errorf("discovery: the identity provider calls itself %q, not %q", md.Issuer, pg.Issuer)
	case md.AuthorizationEndpoint == "" || md.TokenEndpoint == "":
		return nil, errors.New("discovery: no authorization_endpoint or token_endpoint")
	case oauth.CheckURL(md.AuthorizationEndpoint) != nil || oauth.CheckURL(md.TokenEndpoint) != nil:
		return nil, errors.New("discovery: the endpoints must be https URLs")
	case len(md.CodeChallengeMethods) > 0 && !slices.Contains(md.CodeChallengeMethods, "S256"):
		return nil, errors.New("discovery: PKCE with S256 is not supported")
	}
	pg.mu.Lock()
	pg.meta, pg.metaAt = md, pg.now()
	pg.mu.Unlock()
	return md, nil
}

// checkPost refuses a state-changing request that does not come from the
// page itself: it must carry the session's CSRF token, and an Origin
// (or Sec-Fetch-Site) that browsers send with it must name the page.
func (pg *Page) checkPost(w http.ResponseWriter, r *http.Request) *session {
	s := pg.current(r)
	if s == nil {
		pg.page(w, http.StatusForbidden, "Signed out", "Your sign-in on the approval page ended. Open the page again to sign in; nothing was decided.", nil)
		return nil
	}
	for _, o := range r.Header.Values("Origin") {
		if o != pg.Origin {
			pg.page(w, http.StatusForbidden, "Refused", "This request came from another site ("+o+"); nothing was decided.", nil)
			return nil
		}
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		pg.page(w, http.StatusForbidden, "Refused", "This request came from another site; nothing was decided.", nil)
		return nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(s.CSRF)) != 1 {
		pg.page(w, http.StatusForbidden, "Refused", "This request did not come from the approval page (no valid CSRF token); nothing was decided. Open the page again.", nil)
		return nil
	}
	return s
}

func (pg *Page) inbox(w http.ResponseWriter, r *http.Request) {
	s := pg.signedIn(w, r)
	if s == nil {
		return
	}
	pending := pg.Broker.ListPending(r.Context(), s.Approver)
	grants := pg.Broker.ListGrants(r.Context(), s.Approver)
	pg.mu.Lock()
	done := s.done
	s.done = ""
	pg.mu.Unlock()
	pg.render(w, http.StatusOK, inboxTmpl, map[string]any{"S": s, "Pending": pending, "Grants": grants, "Msg": done})
}

func (pg *Page) show(w http.ResponseWriter, r *http.Request) {
	s := pg.signedIn(w, r)
	if s == nil {
		return
	}
	p, err := pg.Broker.GetPending(r.Context(), s.Approver, r.PathValue("id"))
	if err != nil {
		pg.page(w, http.StatusNotFound, "No such approval", "This approval is unknown, already decided or expired, or not yours to decide.", s)
		return
	}
	args := ""
	if p.Args != nil {
		b, _ := json.MarshalIndent(p.Args, "", "  ")
		args = string(b)
	}
	pg.render(w, http.StatusOK, showTmpl, map[string]any{"S": s, "P": p, "Args": args})
}

func (pg *Page) decide(w http.ResponseWriter, r *http.Request) {
	s := pg.checkPost(w, r)
	if s == nil {
		return
	}
	id := r.PathValue("id")
	approve := r.PostFormValue("decision") == "approve"
	if !approve && r.PostFormValue("decision") != "deny" {
		pg.page(w, http.StatusBadRequest, "Refused", `decision must be "approve" or "deny"`, s)
		return
	}
	scope := r.PostFormValue("scope")
	_, err := pg.Broker.ResolveVia(r.Context(), s.Approver, id, approve, scope, Via)
	switch {
	case errors.Is(err, broker.ErrNotFound), errors.Is(err, broker.ErrForbidden):
		pg.page(w, http.StatusNotFound, "No such approval", "This approval is unknown, already decided or expired, or not yours to decide; nothing was decided.", s)
	case errors.Is(err, broker.ErrBadScope):
		pg.page(w, http.StatusBadRequest, "Refused", "The approval does not offer the scope "+scope+"; nothing was decided.", s)
	case err != nil:
		pg.Log.Warn("approval page: deciding", "id", id, "err", err)
		pg.page(w, http.StatusInternalServerError, "Error", "Deciding failed; nothing was decided.", s)
	default:
		done := "denied " + id
		if approve {
			done = "approved " + id + " (scope " + scope + ")"
		}
		pg.flash(s, done)
		http.Redirect(w, r, "/approvals/", http.StatusSeeOther)
	}
}

func (pg *Page) revoke(w http.ResponseWriter, r *http.Request) {
	s := pg.checkPost(w, r)
	if s == nil {
		return
	}
	id := r.PathValue("id")
	if err := pg.Broker.RevokeGrantVia(r.Context(), s.Approver, id, Via); err != nil {
		pg.page(w, http.StatusNotFound, "No such grant", "This grant is unknown, expired, or not yours to revoke.", s)
		return
	}
	pg.flash(s, "revoked "+id)
	http.Redirect(w, r, "/approvals/", http.StatusSeeOther)
}

// flash keeps what a decision did for the inbox to show once: in the
// session, not the URL, so that no link can show a decision that was
// not made.
func (pg *Page) flash(s *session, done string) {
	pg.mu.Lock()
	s.done = done
	pg.mu.Unlock()
}

func (pg *Page) logout(w http.ResponseWriter, r *http.Request) {
	if pg.checkPost(w, r) == nil {
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		pg.mu.Lock()
		delete(pg.sessions, hashKey(c.Value))
		pg.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	pg.page(w, http.StatusOK, "Signed out", "You are signed out of the approval page.", nil)
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashKey is the key a session is kept under: the cookie's hash, so that
// the page's memory holds no cookie value.
func hashKey(v string) string { return hex.EncodeToString(hashBytes(v)) }

func hashBytes(v string) []byte {
	h := sha256.Sum256([]byte(v))
	return h[:]
}
