// Package principal defines the normalised identity on whose behalf a client
// acts. A Principal is exactly what policy sees as input.principal.
//
// See docs/architecture.md, section 5.2.
package principal

// Transport identifies how a client reached the gateway.
type Transport string

const (
	TransportUnix Transport = "unix"
	TransportHTTP Transport = "http"
)

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
	SessionID string `json:"session_id"`
}
