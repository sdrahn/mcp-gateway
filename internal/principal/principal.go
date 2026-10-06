// Package principal defines the normalised identity on whose behalf a client
// acts. A Principal is exactly what policy sees as input.principal.
//
// See docs/architecture.md, section 5.2.
package principal

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"time"
)

// Transport identifies how a client reached the gateway.
type Transport string

const (
	TransportUnix Transport = "unix"
	TransportHTTP Transport = "http"
	// TransportInternal marks the gateway's own principals (e.g. the one
	// shared discovery instances run for).
	TransportInternal Transport = "internal"
)

// Discovery is the identity of the gateway's shared discovery instances
// (and of servers started by mcp-gateway-admin inspect): no user, home "/".
var Discovery = Principal{
	Sub:       "mcp-discovery",
	Home:      "/",
	Transport: TransportInternal,
	SessionID: "discovery",
}

// Client is the self-asserted clientInfo from the MCP initialize request.
// It must never be used as a security boundary.
type Client struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// Principal is an authenticated identity.
type Principal struct {
	// Sub is the subject: the Unix user name for local clients and for
	// remote clients mapped to a local account, else the token subject.
	Sub string `json:"sub"`
	// Issuer is the token issuer of a remote principal.
	Issuer string `json:"iss,omitempty"`
	// UID is the local Unix uid, or nil for a remote principal without a
	// local account mapping.
	UID    *uint32  `json:"uid,omitempty"`
	Groups []string `json:"groups,omitempty"`
	// Scopes are a remote principal's token scopes (its "scope" claim,
	// else "scp"). They never grant; role data may map them to a ceiling
	// (docs/architecture.md, section 6.7).
	Scopes []string `json:"scopes,omitempty"`
	// Home is the home directory of the local account, if any.
	Home string `json:"home,omitempty"`
	// Roles are derived by policy data; the gateway fills them in only when
	// it has resolved them, otherwise policy resolves them itself.
	Roles     []string  `json:"roles,omitempty"`
	Transport Transport `json:"transport"`
	// SELinux is the client's security context (from SO_PEERSEC), empty for
	// remote clients.
	SELinux   string `json:"selinux,omitempty"`
	Client    Client `json:"client"`
	SessionID string `json:"session_id,omitempty"`
	// Cert is the verified TLS client certificate of a remote client that
	// presented one (mTLS).
	Cert *Cert `json:"cert,omitempty"`
	// Expires is when the credential that authenticated the request stops
	// being accepted (a remote principal's token: exp plus the leeway);
	// zero for local principals. Not part of the policy input.
	Expires time.Time `json:"-"`
}

// Cert describes a verified TLS client certificate.
type Cert struct {
	Subject string `json:"subject"`
	// Thumbprint is the certificate's SHA-256 thumbprint, base64url
	// without padding, as in the x5t#S256 confirmation claim (RFC 8705).
	Thumbprint string   `json:"x5t#S256"`
	DNSNames   []string `json:"dns,omitempty"`
	URIs       []string `json:"uris,omitempty"`
	Emails     []string `json:"emails,omitempty"`
}

// Thumbprint returns the x5t#S256 thumbprint of c.
func Thumbprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NewCert describes c.
func NewCert(c *x509.Certificate) *Cert {
	pc := &Cert{Subject: c.Subject.String(), Thumbprint: Thumbprint(c), DNSNames: c.DNSNames, Emails: c.EmailAddresses}
	for _, u := range c.URIs {
		pc.URIs = append(pc.URIs, u.String())
	}
	return pc
}
