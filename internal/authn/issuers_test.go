package authn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// Tokens of several issuers (http.issuers): each validated with its own
// keys, audience, scopes and prefix; an unknown issuer's refused; people
// sign in with http.issuer only.
func TestOAuthIssuers(t *testing.T) {
	org, cluster := newIdP(t), newIdP(t)
	o := NewOAuth(config.HTTP{Issuer: org.srv.URL, Audience: audience, GroupsClaim: "groups", Scopes: []string{"mcp"},
		Issuers: []config.Issuer{{Issuer: cluster.srv.URL, Audience: "mcp-gateway", Scopes: []string{}, SubjectPrefix: "k8s:"}}},
		org.srv.Client())
	ctx := context.Background()

	p, err := o.Authenticate(ctx, org.rsaToken(t, nil), nil)
	if err != nil || p.Sub != "u-123" || p.Issuer != org.srv.URL || p.Groups[0] != "dev" {
		t.Fatalf("the organization's token: %+v %v", p, err)
	}
	// A ServiceAccount token: its own audience, no scope, the prefix.
	sa := map[string]any{"aud": "mcp-gateway", "sub": "system:serviceaccount:agents:custos", "scope": nil}
	p, err = o.Authenticate(ctx, cluster.rsaToken(t, sa), nil)
	if err != nil || p.Sub != "k8s:system:serviceaccount:agents:custos" || p.Issuer != cluster.srv.URL ||
		len(p.Groups) != 1 || p.Groups[0] != "k8s:dev" {
		t.Fatalf("the cluster's token: %+v %v", p, err)
	}

	for name, tok := range map[string]string{
		"the cluster's token for the organization's audience": cluster.rsaToken(t, map[string]any{"scope": nil}),
		"the organization's token for the cluster's audience": org.rsaToken(t, map[string]any{"aud": "mcp-gateway"}),
		"the organization's token without its scope":          org.rsaToken(t, map[string]any{"scope": "openid"}),
		// Signed by the cluster's key, naming the organization: the
		// organization's keys check it.
		"another issuer's key": cluster.rsaToken(t, map[string]any{"iss": org.srv.URL}),
		"an unknown issuer":    cluster.rsaToken(t, map[string]any{"iss": "https://elsewhere.example.com"}),
		"no issuer":            cluster.rsaToken(t, map[string]any{"iss": nil}),
		"not a token":          "not-a-token",
	} {
		if _, err := o.Authenticate(ctx, tok, nil); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !errors.Is(err, ErrInvalidToken) && !errors.Is(err, ErrInsufficientScope) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := o.Authenticate(ctx, cluster.rsaToken(t, map[string]any{"iss": "https://elsewhere.example.com"}), nil); err == nil ||
		!strings.Contains(err.Error(), "not one the gateway accepts") {
		t.Errorf("unknown issuer: %v", err)
	}

	// ID tokens (the approval page): the sign-in issuer only.
	id := map[string]any{"aud": "page-client", "nonce": "n-1", "scope": nil}
	if _, err := o.IDToken(ctx, org.rsaToken(t, id), "page-client", "n-1"); err != nil {
		t.Errorf("the organization's ID token: %v", err)
	}
	if _, err := o.IDToken(ctx, cluster.rsaToken(t, id), "page-client", "n-1"); err == nil {
		t.Error("the cluster's ID token accepted for the page")
	}
}

// Without http.issuer, the first of http.issuers is the one people sign
// in with; without any issuer, every token is refused.
func TestOAuthIssuersOnly(t *testing.T) {
	a, b := newIdP(t), newIdP(t)
	o := NewOAuth(config.HTTP{Audience: audience, GroupsClaim: "groups",
		Issuers: []config.Issuer{{Issuer: a.srv.URL}, {Issuer: b.srv.URL}}}, a.srv.Client())
	ctx := context.Background()
	for _, idp := range []*testIdP{a, b} {
		if _, err := o.Authenticate(ctx, idp.rsaToken(t, nil), nil); err != nil {
			t.Errorf("%s: %v", idp.srv.URL, err)
		}
	}
	id := map[string]any{"aud": "page-client", "nonce": "n-1", "scope": nil}
	if _, err := o.IDToken(ctx, a.rsaToken(t, id), "page-client", "n-1"); err != nil {
		t.Errorf("the first issuer's ID token: %v", err)
	}
	if _, err := o.IDToken(ctx, b.rsaToken(t, id), "page-client", "n-1"); err == nil {
		t.Error("the second issuer's ID token accepted")
	}

	none := NewOAuth(config.HTTP{Audience: audience}, a.srv.Client())
	if _, err := none.Authenticate(ctx, a.rsaToken(t, nil), nil); err == nil {
		t.Error("a token accepted without an issuer")
	}
	if _, err := none.IDToken(ctx, a.rsaToken(t, id), "page-client", "n-1"); err == nil {
		t.Error("an ID token accepted without an issuer")
	}
}

// ca_file: an issuer whose key set a CA outside the system's trust store
// signed (a cluster's API server) is reached with that CA.
func TestOAuthIssuerCAFile(t *testing.T) {
	idp := newIdP(t)
	target, _ := url.Parse(idp.srv.URL)
	keys := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(target))
	t.Cleanup(keys.Close)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: keys.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	token := idp.rsaToken(t, map[string]any{"aud": "mcp-gateway"})
	oauth := func(ca string) *OAuth {
		return NewOAuth(config.HTTP{Audience: audience, GroupsClaim: "groups",
			Issuers: []config.Issuer{{Issuer: idp.srv.URL, Audience: "mcp-gateway", JWKSURL: keys.URL + "/jwks", CAFile: ca}}},
			&http.Client{})
	}
	if _, err := oauth(caFile).Authenticate(ctx, token, nil); err != nil {
		t.Errorf("with ca_file: %v", err)
	}
	if _, err := oauth("").Authenticate(ctx, token, nil); err == nil {
		t.Error("accepted without the CA")
	}
	if _, err := oauth(filepath.Join(t.TempDir(), "missing.crt")).Authenticate(ctx, token, nil); err == nil ||
		!strings.Contains(err.Error(), "ca_file") {
		t.Errorf("a missing ca_file: %v", err)
	}
}

// token_file: the gateway's own token goes with the discovery document
// and key set to the issuer's origin (a cluster's API server asks for
// one), never to a key set elsewhere.
func TestOAuthIssuerTokenFile(t *testing.T) {
	idp := newIdP(t)
	target, _ := url.Parse(idp.srv.URL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	var issuer *httptest.Server
	issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sa-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer.URL, "jwks_uri": issuer.URL + "/jwks"})
			return
		}
		// As a cluster's API server: the key set only to who accepts it.
		if r.URL.Path == "/jwks" && !strings.Contains(r.Header.Get("Accept"), "application/jwk-set+json") {
			w.WriteHeader(http.StatusNotAcceptable)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(issuer.Close)
	var elsewhereAuth atomic.Value
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhereAuth.Store(r.Header.Get("Authorization"))
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(elsewhere.Close)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("sa-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(issuer.Certificate())
	pool.AddCert(elsewhere.Certificate())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	ctx := context.Background()
	token := idp.rsaToken(t, map[string]any{"iss": issuer.URL, "aud": "mcp-gateway"})
	oauth := func(tf, jwks string) *OAuth {
		return NewOAuth(config.HTTP{Audience: audience, GroupsClaim: "groups",
			Issuers: []config.Issuer{{Issuer: issuer.URL, Audience: "mcp-gateway", TokenFile: tf, JWKSURL: jwks}}}, client)
	}
	if _, err := oauth(tokenFile, "").Authenticate(ctx, token, nil); err != nil {
		t.Errorf("with token_file: %v", err)
	}
	if _, err := oauth("", "").Authenticate(ctx, token, nil); err == nil {
		t.Error("accepted though the issuer refused the discovery document")
	}
	if _, err := oauth(tokenFile, elsewhere.URL+"/jwks").Authenticate(ctx, token, nil); err != nil {
		t.Errorf("a key set elsewhere: %v", err)
	}
	if got, _ := elsewhereAuth.Load().(string); got != "" {
		t.Errorf("the token went to a key set on another origin: %q", got)
	}
}
