package config

import (
	"errors"
	"fmt"
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
		if is.SubjectPrefix != "" && !subjectPrefix.MatchString(is.SubjectPrefix) {
			return fmt.Errorf("%s.subject_prefix: %q must be up to 32 letters, digits and ._- followed by a colon (\"partner:\")", key, is.SubjectPrefix)
		}
	}
	if h.LocalUserClaim != "" && h.Issuer == "" {
		return errors.New("http.local_user_claim: applies to the tokens of http.issuer, which is not set; give each of http.issuers its own")
	}
	return nil
}
