package authn

import (
	"context"
	"errors"
	"strings"
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
