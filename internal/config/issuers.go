package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Issuer is one identity provider whose access tokens the HTTP listener
// accepts (http.issuers; docs/architecture.md, section 5.12.4). Each has
// its own audience, key set and claims; a token is validated against the
// issuer its iss claim names.
type Issuer struct {
	// Issuer is the provider's issuer URL, as its tokens' iss claim and
	// its OIDC discovery document name it.
	Issuer string `yaml:"issuer"`
	// Audience the tokens must be for; default http.audience. A
	// cluster's projected ServiceAccount tokens name the audience the
	// pod asked for, any string ("mcp-gateway").
	Audience string `yaml:"audience"`
	// JWKSURL overrides the key set URL of OIDC discovery.
	JWKSURL string `yaml:"jwks_url"`
	// CAFile holds CA certificates (PEM) the issuer's discovery document
	// and key set are trusted with, besides the system's: a cluster's
	// API server, whose certificate its own CA signed (the kube-root-ca.crt
	// ConfigMap of every namespace).
	CAFile string `yaml:"ca_file"`
	// TokenFile holds a bearer token the gateway sends when it fetches
	// the issuer's discovery document and key set, read anew each time:
	// the gateway pod's own projected ServiceAccount token, which a
	// cluster's API server asks for (system:service-account-issuer-
	// discovery). It goes to the issuer's own origin only; a key set
	// elsewhere is fetched without it.
	TokenFile string `yaml:"token_file"`
	// GroupsClaim names the claim with the principal's groups; default
	// http.groups_claim.
	GroupsClaim string `yaml:"groups_claim"`
	// Scopes every token of this issuer must carry; default
	// http.scopes. An empty list ([]) asks for none: ServiceAccount
	// tokens carry no scope.
	Scopes []string `yaml:"scopes"`
	// LocalUserClaim maps a claim to a local account as
	// http.local_user_claim does; not inherited from it, so that a
	// second issuer never names local accounts unless it is meant to.
	LocalUserClaim string `yaml:"local_user_claim"`
	// SubjectPrefix goes before the token's subject and groups, so that
	// the names of two issuers cannot meet in the role data (a user
	// "alice" of a partner's provider as "partner:alice").
	SubjectPrefix string `yaml:"subject_prefix"`
}

// subjectPrefix is a prefix of letters, digits and ._- ending in a
// colon.
var subjectPrefix = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}:$`)

// AllIssuers returns the issuers the listener accepts tokens of, each
// with its defaults filled in: http.issuer first (with the keys of http),
// then http.issuers.
func (h HTTP) AllIssuers() []Issuer {
	var out []Issuer
	if h.Issuer != "" {
		out = append(out, Issuer{Issuer: h.Issuer, Audience: h.Audience, JWKSURL: h.JWKSURL,
			GroupsClaim: h.GroupsClaim, Scopes: h.Scopes, LocalUserClaim: h.LocalUserClaim})
	}
	for _, is := range h.Issuers {
		if is.Audience == "" {
			is.Audience = h.Audience
		}
		if is.GroupsClaim == "" {
			is.GroupsClaim = h.GroupsClaim
		}
		if is.Scopes == nil {
			is.Scopes = h.Scopes
		}
		out = append(out, is)
	}
	return out
}

// SignInIssuer is the issuer people sign in with (the approval page,
// mcp-gateway-admin --gateway): http.issuer, else the first of
// http.issuers; "" without either.
func (h HTTP) SignInIssuer() string {
	if h.Issuer != "" {
		return h.Issuer
	}
	if len(h.Issuers) > 0 {
		return h.Issuers[0].Issuer
	}
	return ""
}

// signInIssuerWarning warns when the issuer people sign in with looks
// like a cluster's (#412): without http.issuer that is the first of
// http.issuers, and one that asks for no scope (as ServiceAccount
// tokens carry none) or fetches its keys with a token_file is one. Anyone
// who may create a pod in that cluster can have a token of it for any
// audience, the device client's (approvals.page.device_client_id) too,
// and would be taken for a person signing in.
func (h HTTP) signInIssuerWarning() string {
	if h.Issuer != "" || len(h.Issuers) == 0 {
		return ""
	}
	is := h.Issuers[0]
	if (is.Scopes == nil || len(is.Scopes) > 0) && is.TokenFile == "" {
		return ""
	}
	return fmt.Sprintf("http.issuers[0] (%s) is the issuer people sign in with (there is no http.issuer), and looks like a cluster's "+
		"(no scopes, or a token_file): anyone who may create a pod there could sign in as a person with its ServiceAccount token; "+
		"set the people's identity provider as http.issuer, or first in http.issuers", is.Issuer)
}

// validateIssuers checks http.issuers: URLs, no issuer twice, prefixes.
func (h HTTP) validateIssuers() error {
	seen := []string{h.Issuer}
	for i, is := range h.Issuers {
		key := fmt.Sprintf("http.issuers[%d]", i)
		if is.Issuer == "" {
			return fmt.Errorf("%s.issuer: required", key)
		}
		if slices.Contains(seen, is.Issuer) {
			return fmt.Errorf("%s.issuer: %s is named twice; an issuer's tokens are validated one way", key, is.Issuer)
		}
		seen = append(seen, is.Issuer)
		// The audience is any string a token's aud names (a projected
		// ServiceAccount token's is what its pod asked for), not
		// necessarily a URL.
		if strings.ContainsAny(is.Audience, " \t\r\n") {
			return fmt.Errorf("%s.audience: %q has a space or a line break", key, is.Audience)
		}
		for name, v := range map[string]string{"issuer": is.Issuer, "jwks_url": is.JWKSURL} {
			if v == "" {
				continue
			}
			if err := checkURL(v); err != nil {
				return fmt.Errorf("%s.%s: %w", key, name, err)
			}
		}
		if is.CAFile != "" && !filepath.IsAbs(is.CAFile) {
			return fmt.Errorf("%s.ca_file: must be an absolute path, got %q", key, is.CAFile)
		}
		if is.TokenFile != "" && !filepath.IsAbs(is.TokenFile) {
			return fmt.Errorf("%s.token_file: must be an absolute path, got %q", key, is.TokenFile)
		}
		if is.TokenFile != "" && !strings.HasPrefix(is.Issuer, "https://") {
			return fmt.Errorf("%s.token_file: only for an https:// issuer (the token would go in the clear)", key)
		}
		if is.SubjectPrefix != "" && !subjectPrefix.MatchString(is.SubjectPrefix) {
			return fmt.Errorf("%s.subject_prefix: %q must be up to 32 letters, digits and ._- followed by a colon (\"partner:\")", key, is.SubjectPrefix)
		}
	}
	if h.LocalUserClaim != "" && h.Issuer == "" {
		return errors.New("http.local_user_claim: applies to the tokens of http.issuer, which is not set; give each of http.issuers its own")
	}
	return nil
}
