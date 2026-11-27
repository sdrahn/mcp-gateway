package authn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

// Token validation errors. ErrInvalidToken maps to HTTP 401 with
// error="invalid_token", ErrInsufficientScope to 403 with
// error="insufficient_scope" (RFC 6750).
var (
	ErrInvalidToken      = transport.ErrInvalidToken
	ErrInsufficientScope = transport.ErrInsufficientScope
)

// Asymmetric algorithms only: no "none", no HMAC (whose key would be the
// public key in a key-confusion attack).
var allowedAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

const (
	leeway          = time.Minute
	keysMaxAge      = time.Hour
	keysMinInterval = 30 * time.Second
)

// OAuth validates bearer tokens as an OAuth 2.1 resource server. It never
// issues tokens and never forwards them. It accepts the tokens of every
// configured issuer (http.issuer and http.issuers), each validated with
// its own key set, audience and claims.
type OAuth struct {
	cfg    config.HTTP
	client *http.Client
	now    func() time.Time

	// issuers by issuer URL; signIn is the one people sign in with
	// (ID tokens of the approval page and the command line).
	issuers map[string]*issuerKeys
	signIn  *issuerKeys
}

// issuerKeys is one issuer's settings and key set.
type issuerKeys struct {
	o   *OAuth
	cfg config.Issuer
	// client fetches the issuer's discovery document and key set: o's,
	// or one trusting the issuer's ca_file (clientErr if it cannot be
	// read).
	client    *http.Client
	clientErr error

	mu        sync.Mutex
	jwksURL   string
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
}

// NewOAuth returns a validator for the tokens of cfg's issuers
// (cfg.AllIssuers), each for its audience.
func NewOAuth(cfg config.HTTP, client *http.Client) *OAuth {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	o := &OAuth{cfg: cfg, client: client, now: time.Now, issuers: map[string]*issuerKeys{}}
	for _, is := range cfg.AllIssuers() {
		k := &issuerKeys{o: o, cfg: is, jwksURL: is.JWKSURL, client: client}
		if is.CAFile != "" {
			k.client, k.clientErr = clientWithCA(client, is.CAFile)
		}
		o.issuers[is.Issuer] = k
	}
	o.signIn = o.issuers[cfg.SignInIssuer()]
	if o.signIn == nil {
		// No issuer at all: every token is refused.
		o.signIn = &issuerKeys{o: o}
	}
	return o
}

// clientWithCA is base trusting the CA certificates in caFile besides the
// system's.
func clientWithCA(base *http.Client, caFile string) (*http.Client, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("ca_file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ca_file: %s has no PEM certificate", caFile)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	c := *base
	c.Transport = tr
	return &c, nil
}

// issuerOf returns the issuer the token's iss claim names, read before
// the signature is checked (the issuer's keys check it then).
func (o *OAuth) issuerOf(token string) (*issuerKeys, error) {
	unverified := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, unverified); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	iss, _ := unverified["iss"].(string)
	is := o.issuers[iss]
	if is == nil {
		return nil, fmt.Errorf("%w: issuer %q is not one the gateway accepts tokens of", ErrInvalidToken, iss)
	}
	return is, nil
}

// Authenticate validates token and returns the principal it represents.
// The session id is left empty for the transport to fill in.
func (o *OAuth) Authenticate(ctx context.Context, token string, cert *x509.Certificate) (principal.Principal, error) {
	is, err := o.issuerOf(token)
	if err != nil {
		return principal.Principal{}, err
	}
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims,
		func(t *jwt.Token) (any, error) { return is.key(ctx, t) },
		jwt.WithValidMethods(allowedAlgs),
		jwt.WithIssuer(is.cfg.Issuer),
		jwt.WithAudience(is.cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(leeway),
		jwt.WithTimeFunc(o.now),
	)
	if err != nil {
		return principal.Principal{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return principal.Principal{}, fmt.Errorf("%w: no subject", ErrInvalidToken)
	}
	if err := o.checkBinding(claims, cert); err != nil {
		return principal.Principal{}, err
	}
	scopes := claimStrings(claims, "scope")
	if len(scopes) == 0 {
		scopes = claimStrings(claims, "scp")
	}
	for _, want := range is.cfg.Scopes {
		if !slices.Contains(scopes, want) {
			// What an administrator needs to fix the client or the
			// identity provider: whose token, from which client, with
			// which scopes.
			client, _ := claims["azp"].(string)
			return principal.Principal{}, fmt.Errorf("%w: missing scope %q (the token of %q from client %q has %q)",
				ErrInsufficientScope, want, sub, client, strings.Join(scopes, " "))
		}
	}

	p, err := is.principalOf(claims, sub)
	if err != nil {
		return principal.Principal{}, err
	}
	p.Scopes = scopes
	return p, nil
}

// principalOf is the principal claims (validated, with subject sub) make:
// the token's groups, and the local account local_user_claim names. A
// token naming root or a system account is refused: whoever may choose
// their name at the identity provider would otherwise run as it. The
// issuer's subject_prefix goes before the subject and the groups of the
// token (not before a local account's).
func (is *issuerKeys) principalOf(claims jwt.MapClaims, sub string) (principal.Principal, error) {
	groups := claimStrings(claims, is.cfg.GroupsClaim)
	if pre := is.cfg.SubjectPrefix; pre != "" {
		sub = pre + sub
		for i := range groups {
			groups[i] = pre + groups[i]
		}
	}
	p := principal.Principal{
		Sub:       sub,
		Issuer:    is.cfg.Issuer,
		Groups:    groups,
		Transport: principal.TransportHTTP,
	}
	// Required and valid (checked above): streams the request opens end
	// when the token is no longer accepted.
	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		p.Expires = exp.Add(leeway)
	}
	if is.cfg.LocalUserClaim != "" {
		if name, _ := claims[is.cfg.LocalUserClaim].(string); name != "" {
			if err := mapLocalUser(&p, name); err != nil {
				return principal.Principal{}, err
			}
		}
	}
	return p, nil
}

// IDToken validates an ID token the approval page got for its client
// clientID with nonce (OpenID Connect Core, section 3.1.3.7): signed by a
// key of the issuer's key set, for clientID (azp too when it names more
// audiences), not expired, with the nonce. It returns the principal its
// claims make, as for an access token (groups, local account), without
// scopes: an ID token authorizes nothing by itself.
func (o *OAuth) IDToken(ctx context.Context, raw, clientID, nonce string) (principal.Principal, error) {
	if nonce == "" {
		return principal.Principal{}, fmt.Errorf("%w: nonce does not match", ErrInvalidToken)
	}
	return o.idToken(ctx, raw, clientID, &nonce)
}

// ApproverToken validates an ID token that the command line, signed in
// as the client clientID with the device flow, sends as its bearer token
// to the approval API (docs/architecture.md, step 39 stage D): as
// IDToken, but without a nonce, which the device flow has none of. Only
// tokens for clientID pass: an agent's access token (for http.audience)
// is not one.
func (o *OAuth) ApproverToken(ctx context.Context, raw, clientID string) (principal.Principal, error) {
	return o.idToken(ctx, raw, clientID, nil)
}

// idToken validates an ID token for clientID; with nonce, it must carry
// that nonce.
func (o *OAuth) idToken(ctx context.Context, raw, clientID string, nonce *string) (principal.Principal, error) {
	if clientID == "" {
		return principal.Principal{}, fmt.Errorf("%w: no client", ErrInvalidToken)
	}
	// People sign in with one issuer (http.issuer, else the first of
	// http.issuers).
	is := o.signIn
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, claims,
		func(t *jwt.Token) (any, error) { return is.key(ctx, t) },
		jwt.WithValidMethods(allowedAlgs),
		jwt.WithIssuer(is.cfg.Issuer),
		jwt.WithAudience(clientID),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(leeway),
		jwt.WithTimeFunc(o.now),
	)
	if err != nil {
		return principal.Principal{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if aud, _ := claims.GetAudience(); len(aud) > 1 {
		if azp, _ := claims["azp"].(string); azp != clientID {
			return principal.Principal{}, fmt.Errorf("%w: azp %q is not the client %q", ErrInvalidToken, azp, clientID)
		}
	}
	if nonce != nil {
		got, _ := claims["nonce"].(string)
		if subtle.ConstantTimeCompare([]byte(got), []byte(*nonce)) != 1 {
			return principal.Principal{}, fmt.Errorf("%w: nonce does not match", ErrInvalidToken)
		}
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return principal.Principal{}, fmt.Errorf("%w: no subject", ErrInvalidToken)
	}
	return is.principalOf(claims, sub)
}

// checkBinding enforces certificate-bound tokens (RFC 8705): a token
// with a x5t#S256 confirmation is only accepted over a TLS connection
// with that client certificate; with require_bound_tokens, unbound
// tokens are refused.
func (o *OAuth) checkBinding(claims jwt.MapClaims, cert *x509.Certificate) error {
	var want string
	if cnf, ok := claims["cnf"].(map[string]any); ok {
		want, _ = cnf["x5t#S256"].(string)
	}
	switch {
	case want == "" && o.cfg.RequireBoundTokens:
		return fmt.Errorf("%w: token is not certificate-bound", ErrInvalidToken)
	case want == "":
		return nil
	case cert == nil:
		return fmt.Errorf("%w: certificate-bound token without client certificate", ErrInvalidToken)
	case subtle.ConstantTimeCompare([]byte(principal.Thumbprint(cert)), []byte(want)) != 1:
		return fmt.Errorf("%w: token is bound to another client certificate", ErrInvalidToken)
	}
	return nil
}

// mapLocalUser makes p run as the local account name, if it exists
// (decision D1): subject, uid and home of the account, plus its groups.
// An account outside UID_MIN..UID_MAX of login.defs (root, system
// accounts, nobody) is an error.
func mapLocalUser(p *principal.Principal, name string) error {
	u, err := user.Lookup(name)
	if err != nil {
		return nil
	}
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil
	}
	uid := uint32(uid64)
	if lo, hi := peopleUIDs(); uid < lo || uid > hi {
		return fmt.Errorf("%w: local_user_claim names account %s (uid %d), not an account of a person (UID_MIN %d to UID_MAX %d of login.defs)",
			ErrInvalidToken, u.Username, uid, lo, hi)
	}
	p.Sub, p.UID, p.Home = u.Username, &uid, u.HomeDir
	if gids, err := u.GroupIds(); err == nil {
		for _, gid := range gids {
			if g, err := user.LookupGroupId(gid); err == nil && !slices.Contains(p.Groups, g.Name) {
				p.Groups = append(p.Groups, g.Name)
			}
		}
	}
	return nil
}

// claimStrings reads a claim that is a list of strings or a
// space-separated string.
func claimStrings(c jwt.MapClaims, name string) []string {
	switch v := c[name].(type) {
	case string:
		return strings.Fields(v)
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// key returns the verification key for t, refreshing the key set when the
// key id is unknown (rate limited) or the set is old.
func (is *issuerKeys) key(ctx context.Context, t *jwt.Token) (any, error) {
	if is.cfg.Issuer == "" {
		return nil, errors.New("no issuer configured")
	}
	kid, _ := t.Header["kid"].(string)
	is.mu.Lock()
	defer is.mu.Unlock()

	now := is.o.now()
	stale := now.Sub(is.fetchedAt) > keysMaxAge
	k, found := is.lookup(kid)
	if !found || stale {
		if is.keys == nil || now.Sub(is.fetchedAt) > keysMinInterval {
			if err := is.refresh(ctx); err != nil && is.keys == nil {
				return nil, err
			}
			k, found = is.lookup(kid)
		}
	}
	if !found {
		return nil, fmt.Errorf("unknown key %q", kid)
	}
	return k, nil
}

func (is *issuerKeys) lookup(kid string) (crypto.PublicKey, bool) {
	if kid == "" && len(is.keys) == 1 {
		for _, k := range is.keys {
			return k, true
		}
	}
	k, ok := is.keys[kid]
	return k, ok
}

func (is *issuerKeys) refresh(ctx context.Context) error {
	o := is.o
	is.fetchedAt = o.now()
	if is.clientErr != nil {
		return is.clientErr
	}
	if is.jwksURL == "" {
		var meta struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		if err := is.getJSON(ctx, strings.TrimSuffix(is.cfg.Issuer, "/")+"/.well-known/openid-configuration", &meta); err != nil {
			return fmt.Errorf("oidc discovery: %w", err)
		}
		if meta.Issuer != is.cfg.Issuer {
			return fmt.Errorf("oidc discovery: issuer %q does not match %q", meta.Issuer, is.cfg.Issuer)
		}
		if meta.JWKSURI == "" {
			return errors.New("oidc discovery: no jwks_uri")
		}
		is.jwksURL = meta.JWKSURI
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := is.getJSON(ctx, is.jwksURL, &set); err != nil {
		return fmt.Errorf("fetching key set: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			continue // skip keys we cannot use
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return errors.New("key set has no usable signing keys")
	}
	is.keys = keys
	return nil
}

func (is *issuerKeys) getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := is.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

// jwk is a JSON Web Key (RFC 7517) with the members needed for RSA, EC and
// Ed25519 public keys.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b64(k.E)
		if err != nil || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("bad RSA exponent")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < 2048 {
			return nil, errors.New("RSA key too small")
		}
		return pub, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}
		x, err := b64(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64(k.Y)
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !curve.IsOnCurve(pub.X, pub.Y) { //nolint:staticcheck // validating untrusted input
			return nil, errors.New("EC point not on curve")
		}
		return pub, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}
		x, err := b64(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("bad Ed25519 key")
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, fmt.Errorf("unsupported key type %q", k.Kty)
}
