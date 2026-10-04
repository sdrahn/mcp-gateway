// Package oauth is the client side of OAuth 2.1 as the gateway uses it to
// sign principals in to MCP servers defined with url (docs/architecture.md,
// section 5.7.3): the messages between the gateway and mcp-oauth-helper,
// which makes every request to the server and its authorization server
// (Do), PKCE, and the authorization URL the principal opens.
package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Operations of the helper (Request.Op).
const (
	// OpResource fetches the protected resource metadata (RFC 9728) of
	// the MCP server at URL.
	OpResource = "resource"
	// OpServer fetches the metadata of the authorization server whose
	// issuer is URL (RFC 8414, else OpenID Connect discovery).
	OpServer = "server"
	// OpRegister registers a client at the registration endpoint URL
	// (RFC 7591).
	OpRegister = "register"
	// OpToken asks the token endpoint URL for tokens: for an
	// authorization code or with a refresh token.
	OpToken = "token"
	// OpRevoke revokes a token at the revocation endpoint URL (RFC 7009).
	OpRevoke = "revoke"
)

// Request is one step for the helper, a JSON object on its stdin.
type Request struct {
	Op  string `json:"op"`
	URL string `json:"url"`

	// OpRegister.
	RedirectURI string `json:"redirect_uri,omitempty"`
	ClientName  string `json:"client_name,omitempty"`

	// OpToken: GrantType "authorization_code" (Code, CodeVerifier,
	// RedirectURI) or "refresh_token" (RefreshToken).
	GrantType    string `json:"grant_type,omitempty"`
	Code         string `json:"code,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`

	// OpRevoke.
	Token         string `json:"token,omitempty"`
	TokenTypeHint string `json:"token_type_hint,omitempty"`

	// OpRegister, OpToken.
	Scope string `json:"scope,omitempty"`
	// OpToken: the resource indicator (RFC 8707), the server's URL.
	Resource string `json:"resource,omitempty"`

	// The client (OpToken, OpRevoke): its id, and its secret, given as is
	// (a registered client's) or as the name of a credential of the
	// helper's unit (ClientSecretCredential, from the definition).
	ClientID               string `json:"client_id,omitempty"`
	ClientSecret           string `json:"client_secret,omitempty"`
	ClientSecretCredential string `json:"client_secret_credential,omitempty"`
}

// Response is the helper's answer, a JSON object on its stdout: Error
// (an OAuth error code, or "helper_error" for anything else) or what the
// operation returns.
type Response struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`

	Resource *ResourceMetadata `json:"resource,omitempty"`
	Server   *ServerMetadata   `json:"server,omitempty"`
	Client   *Client           `json:"client,omitempty"`
	Token    *Token            `json:"token,omitempty"`
}

// Err returns the response's error, or nil.
func (r Response) Err() error {
	if r.Error == "" {
		return nil
	}
	return &Error{Code: r.Error, Description: r.ErrorDescription}
}

// Error is an error the authorization server (or the helper) reported.
type Error struct {
	Code        string
	Description string
}

func (e *Error) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

// HelperError is the code of errors that are not the authorization
// server's (a connection failed, an answer was malformed).
const HelperError = "helper_error"

// IsInvalidGrant reports whether err says a code or refresh token is no
// longer valid: the principal must sign in again.
func IsInvalidGrant(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == "invalid_grant"
}

// ResourceMetadata is what the gateway uses of a protected resource's
// metadata (RFC 9728).
type ResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported,omitempty"`
}

// ServerMetadata is what the gateway uses of an authorization server's
// metadata (RFC 8414).
type ServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ClientIDMetadataDocumentSupported bool     `json:"client_id_metadata_document_supported,omitempty"`
}

// Check verifies what the gateway relies on: the endpoints are URLs it
// may use, and PKCE with S256 is supported.
func (m *ServerMetadata) Check() error {
	for name, u := range map[string]string{"authorization_endpoint": m.AuthorizationEndpoint, "token_endpoint": m.TokenEndpoint} {
		if err := CheckURL(u); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	for name, u := range map[string]string{"registration_endpoint": m.RegistrationEndpoint, "revocation_endpoint": m.RevocationEndpoint} {
		if u != "" {
			if err := CheckURL(u); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	if !slices.Contains(m.CodeChallengeMethodsSupported, "S256") {
		return errors.New("the authorization server does not support PKCE with S256 (code_challenge_methods_supported)")
	}
	return nil
}

// Client is a registered client (RFC 7591).
type Client struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
}

// Token is a token response (RFC 6749, section 5.1), with ExpiresIn
// turned into Expiry by the gateway.
type Token struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	Expiry       time.Time `json:"expiry,omitzero"`
}

// CheckURL accepts the URLs the helper may be sent to: https, or http on
// the local host.
func CheckURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil {
		return fmt.Errorf("%q is not an absolute URL without user information", s)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return fmt.Errorf("%q must be an https URL (http only on the local host)", s)
}

// SameOrigin reports whether a and b have the same scheme, host and port.
func SameOrigin(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	return err1 == nil && err2 == nil && ua.Scheme == ub.Scheme && strings.EqualFold(ua.Host, ub.Host)
}

// NewVerifier returns a PKCE code verifier (RFC 7636): 32 random bytes,
// base64url.
func NewVerifier() string { return randomString(32) }

// NewState returns an unguessable state value (128 bits).
func NewState() string { return randomString(16) }

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Challenge returns the S256 code challenge of verifier.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AuthParams are the parameters of an authorization request.
type AuthParams struct {
	ClientID    string
	RedirectURI string
	Scope       string
	State       string
	Verifier    string
	Resource    string
}

// AuthURL returns the URL of the authorization request at endpoint
// (authorization code with PKCE S256 and a resource indicator).
func AuthURL(endpoint string, p AuthParams) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", p.RedirectURI)
	if p.Scope != "" {
		q.Set("scope", p.Scope)
	}
	q.Set("state", p.State)
	q.Set("code_challenge", Challenge(p.Verifier))
	q.Set("code_challenge_method", "S256")
	if p.Resource != "" {
		q.Set("resource", p.Resource)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
