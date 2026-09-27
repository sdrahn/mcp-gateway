package authn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
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
// issues tokens and never forwards them.
type OAuth struct {
	cfg    config.HTTP
	client *http.Client
	now    func() time.Time

	mu        sync.Mutex
	jwksURL   string
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
}

// NewOAuth returns a validator for tokens from cfg.Issuer for
// cfg.Audience.
func NewOAuth(cfg config.HTTP, client *http.Client) *OAuth {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &OAuth{cfg: cfg, client: client, now: time.Now, jwksURL: cfg.JWKSURL}
}

// Authenticate validates token and returns the principal it represents.
// The session id is left empty for the transport to fill in.
func (o *OAuth) Authenticate(ctx context.Context, token string) (principal.Principal, error) {
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims,
		func(t *jwt.Token) (any, error) { return o.key(ctx, t) },
		jwt.WithValidMethods(allowedAlgs),
		jwt.WithIssuer(o.cfg.Issuer),
		jwt.WithAudience(o.cfg.Audience),
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
	scopes := claimStrings(claims, "scope")
	if len(scopes) == 0 {
		scopes = claimStrings(claims, "scp")
	}
	for _, want := range o.cfg.Scopes {
		if !slices.Contains(scopes, want) {
			return principal.Principal{}, fmt.Errorf("%w: missing scope %q", ErrInsufficientScope, want)
		}
	}

	p := principal.Principal{
		Sub:       sub,
		Issuer:    o.cfg.Issuer,
		Groups:    claimStrings(claims, o.cfg.GroupsClaim),
		Transport: principal.TransportHTTP,
	}
	if o.cfg.LocalUserClaim != "" {
		if name, _ := claims[o.cfg.LocalUserClaim].(string); name != "" {
			mapLocalUser(&p, name)
		}
	}
	return p, nil
}

// mapLocalUser makes p run as the local account name, if it exists
// (decision D1): subject, uid and home of the account, plus its groups.
func mapLocalUser(p *principal.Principal, name string) {
	u, err := user.Lookup(name)
	if err != nil {
		return
	}
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return
	}
	uid := uint32(uid64)
	p.Sub, p.UID, p.Home = u.Username, &uid, u.HomeDir
	if gids, err := u.GroupIds(); err == nil {
		for _, gid := range gids {
			if g, err := user.LookupGroupId(gid); err == nil && !slices.Contains(p.Groups, g.Name) {
				p.Groups = append(p.Groups, g.Name)
			}
		}
	}
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
func (o *OAuth) key(ctx context.Context, t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	o.mu.Lock()
	defer o.mu.Unlock()

	stale := o.now().Sub(o.fetchedAt) > keysMaxAge
	k, found := o.lookup(kid)
	if !found || stale {
		if o.keys == nil || o.now().Sub(o.fetchedAt) > keysMinInterval {
			if err := o.refresh(ctx); err != nil && o.keys == nil {
				return nil, err
			}
			k, found = o.lookup(kid)
		}
	}
	if !found {
		return nil, fmt.Errorf("unknown key %q", kid)
	}
	return k, nil
}

func (o *OAuth) lookup(kid string) (crypto.PublicKey, bool) {
	if kid == "" && len(o.keys) == 1 {
		for _, k := range o.keys {
			return k, true
		}
	}
	k, ok := o.keys[kid]
	return k, ok
}

func (o *OAuth) refresh(ctx context.Context) error {
	o.fetchedAt = o.now()
	if o.jwksURL == "" {
		var meta struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}
		if err := o.getJSON(ctx, strings.TrimSuffix(o.cfg.Issuer, "/")+"/.well-known/openid-configuration", &meta); err != nil {
			return fmt.Errorf("oidc discovery: %w", err)
		}
		if meta.Issuer != o.cfg.Issuer {
			return fmt.Errorf("oidc discovery: issuer %q does not match %q", meta.Issuer, o.cfg.Issuer)
		}
		if meta.JWKSURI == "" {
			return errors.New("oidc discovery: no jwks_uri")
		}
		o.jwksURL = meta.JWKSURI
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := o.getJSON(ctx, o.jwksURL, &set); err != nil {
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
	o.keys = keys
	return nil
}

func (o *OAuth) getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := o.client.Do(req)
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
