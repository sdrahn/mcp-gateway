package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os/user"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

const audience = "https://gw.example.com/mcp"

// testIdP serves OIDC discovery and a JWKS with one RSA and one EC key.
type testIdP struct {
	srv       *httptest.Server
	rsaKey    *rsa.PrivateKey
	ecKey     *ecdsa.PrivateKey
	jwksHits  atomic.Int32
	publishEC atomic.Bool
}

func newIdP(t *testing.T) *testIdP {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	idp := &testIdP{rsaKey: rk, ecKey: ek}
	idp.publishEC.Store(true)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": idp.srv.URL, "jwks_uri": idp.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		idp.jwksHits.Add(1)
		enc := base64.RawURLEncoding.EncodeToString
		keys := []map[string]string{{
			"kty": "RSA", "kid": "rsa1", "use": "sig",
			"n": enc(rk.N.Bytes()), "e": enc(big.NewInt(int64(rk.E)).Bytes()),
		}}
		if idp.publishEC.Load() {
			keys = append(keys, map[string]string{
				"kty": "EC", "kid": "ec1", "crv": "P-256",
				"x": enc(ek.X.FillBytes(make([]byte, 32))), "y": enc(ek.Y.FillBytes(make([]byte, 32))),
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

func (idp *testIdP) claims(overrides map[string]any) jwt.MapClaims {
	c := jwt.MapClaims{
		"iss":    idp.srv.URL,
		"aud":    audience,
		"sub":    "u-123",
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
		"groups": []string{"dev"},
		"scope":  "openid mcp",
	}
	for k, v := range overrides {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func (idp *testIdP) rsaToken(t *testing.T, overrides map[string]any) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, idp.claims(overrides))
	tok.Header["kid"] = "rsa1"
	s, err := tok.SignedString(idp.rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (idp *testIdP) oauth(mod func(*config.HTTP)) *OAuth {
	cfg := config.HTTP{Issuer: idp.srv.URL, Audience: audience, GroupsClaim: "groups"}
	if mod != nil {
		mod(&cfg)
	}
	return NewOAuth(cfg, idp.srv.Client())
}

func TestOAuthValid(t *testing.T) {
	idp := newIdP(t)
	p, err := idp.oauth(nil).Authenticate(context.Background(), idp.rsaToken(t, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Sub != "u-123" || p.Issuer != idp.srv.URL || p.Transport != "http" || p.UID != nil || len(p.Groups) != 1 || p.Groups[0] != "dev" {
		t.Fatalf("principal %+v", p)
	}

	// The principal carries when the token stops being accepted.
	exp := time.Now().Add(10 * time.Minute).Truncate(time.Second)
	p, err = idp.oauth(nil).Authenticate(context.Background(), idp.rsaToken(t, map[string]any{"exp": exp.Unix()}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Expires.Equal(exp.Add(leeway)) {
		t.Errorf("Expires %v, want %v", p.Expires, exp.Add(leeway))
	}
}

func TestOAuthEC(t *testing.T) {
	idp := newIdP(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, idp.claims(nil))
	tok.Header["kid"] = "ec1"
	s, err := tok.SignedString(idp.ecKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := idp.oauth(nil).Authenticate(context.Background(), s, nil); err != nil {
		t.Fatal(err)
	}
}

func TestOAuthRejects(t *testing.T) {
	idp := newIdP(t)
	o := idp.oauth(nil)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)

	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, idp.claims(nil))
	forged.Header["kid"] = "rsa1"
	forgedS, _ := forged.SignedString(other)

	none := jwt.NewWithClaims(jwt.SigningMethodNone, idp.claims(nil))
	noneS, _ := none.SignedString(jwt.UnsafeAllowNoneSignatureType)

	// Key confusion: HMAC signed with the public modulus.
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, idp.claims(nil))
	hs.Header["kid"] = "rsa1"
	hsS, _ := hs.SignedString(idp.rsaKey.N.Bytes())

	tests := map[string]string{
		"wrong audience": idp.rsaToken(t, map[string]any{"aud": "https://other/mcp"}),
		"wrong issuer":   idp.rsaToken(t, map[string]any{"iss": "https://evil"}),
		"expired":        idp.rsaToken(t, map[string]any{"exp": time.Now().Add(-2 * time.Minute).Unix()}),
		"no expiry":      idp.rsaToken(t, map[string]any{"exp": nil}),
		"not yet valid":  idp.rsaToken(t, map[string]any{"nbf": time.Now().Add(5 * time.Minute).Unix()}),
		"no subject":     idp.rsaToken(t, map[string]any{"sub": nil}),
		"forged":         forgedS,
		"alg none":       noneS,
		"hmac confusion": hsS,
		"garbage":        "not.a.jwt",
	}
	for name, tok := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := o.Authenticate(context.Background(), tok, nil); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("want ErrInvalidToken, got %v", err)
			}
		})
	}
}

func TestOAuthScopes(t *testing.T) {
	idp := newIdP(t)
	o := idp.oauth(func(c *config.HTTP) { c.Scopes = []string{"mcp"} })
	if _, err := o.Authenticate(context.Background(), idp.rsaToken(t, nil), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Authenticate(context.Background(), idp.rsaToken(t, map[string]any{"scope": "openid"}), nil); !errors.Is(err, ErrInsufficientScope) {
		t.Fatalf("want ErrInsufficientScope, got %v", err)
	}
	if _, err := o.Authenticate(context.Background(), idp.rsaToken(t, map[string]any{"scope": nil, "scp": []string{"mcp"}}), nil); err != nil {
		t.Fatalf("scp array: %v", err)
	}
}

func TestOAuthKeyRefresh(t *testing.T) {
	idp := newIdP(t)
	idp.publishEC.Store(false)
	o := idp.oauth(nil)
	if _, err := o.Authenticate(context.Background(), idp.rsaToken(t, nil), nil); err != nil {
		t.Fatal(err)
	}
	// The IdP rotates in the EC key; an unknown kid triggers a refresh, but
	// not more often than keysMinInterval.
	idp.publishEC.Store(true)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, idp.claims(nil))
	tok.Header["kid"] = "ec1"
	s, _ := tok.SignedString(idp.ecKey)
	if _, err := o.Authenticate(context.Background(), s, nil); err == nil {
		t.Fatal("refresh should be rate limited")
	}
	o.now = func() time.Time { return time.Now().Add(keysMinInterval + time.Second) }
	if _, err := o.Authenticate(context.Background(), s, nil); err != nil {
		t.Fatalf("after refresh: %v", err)
	}
	if n := idp.jwksHits.Load(); n != 2 {
		t.Fatalf("JWKS fetched %d times, want 2", n)
	}
}

func TestOAuthLocalUserMapping(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	idp := newIdP(t)
	o := idp.oauth(func(c *config.HTTP) { c.LocalUserClaim = "preferred_username" })
	p, err := o.Authenticate(context.Background(), idp.rsaToken(t, map[string]any{"preferred_username": me.Username}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Sub != me.Username || p.UID == nil || p.Home != me.HomeDir {
		t.Fatalf("mapped principal %+v", p)
	}
	p, err = o.Authenticate(context.Background(), idp.rsaToken(t, map[string]any{"preferred_username": "no-such-user-xyz"}), nil)
	if err != nil || p.Sub != "u-123" || p.UID != nil {
		t.Fatalf("unmapped principal %+v %v", p, err)
	}
}

func testCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCertificateBoundTokens(t *testing.T) {
	idp := newIdP(t)
	mine, other := testCert(t, "mine"), testCert(t, "other")
	boundToMine := idp.rsaToken(t, map[string]any{"cnf": map[string]any{"x5t#S256": principal.Thumbprint(mine)}})
	unbound := idp.rsaToken(t, nil)

	o := idp.oauth(nil)
	for name, tc := range map[string]struct {
		token string
		cert  *x509.Certificate
		ok    bool
	}{
		"bound, its certificate":   {boundToMine, mine, true},
		"bound, other certificate": {boundToMine, other, false},
		"bound, no certificate":    {boundToMine, nil, false},
		"unbound, certificate":     {unbound, mine, true},
		"unbound, no certificate":  {unbound, nil, true},
	} {
		_, err := o.Authenticate(context.Background(), tc.token, tc.cert)
		if tc.ok != (err == nil) || (err != nil && !errors.Is(err, ErrInvalidToken)) {
			t.Errorf("%s: %v", name, err)
		}
	}

	strict := idp.oauth(func(c *config.HTTP) { c.RequireBoundTokens = true })
	if _, err := strict.Authenticate(context.Background(), unbound, mine); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("unbound token accepted with require_bound_tokens: %v", err)
	}
	if _, err := strict.Authenticate(context.Background(), boundToMine, mine); err != nil {
		t.Errorf("bound token refused with require_bound_tokens: %v", err)
	}
}
