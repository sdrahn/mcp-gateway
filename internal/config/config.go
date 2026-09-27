// Package config loads the gateway configuration and the backend registry.
//
// See docs/architecture.md, sections 5.1, 5.5 and 5.7.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Default paths. Vendor files live below /usr (read-only, owned by
// packages), administrator files below /etc; see Resolve and LoadBackends.
const (
	DefaultConfigPath       = "/etc/mcp-gateway/gateway.yaml"
	DefaultVendorConfigPath = "/usr/etc/mcp-gateway/gateway.yaml"
	DefaultServersDir       = "/etc/mcp-gateway/servers.d"
	DefaultVendorServersDir = "/usr/share/mcp-gateway/servers.d"
	DefaultSocket           = "/run/mcp-gateway/mcp.sock"
	DefaultOPASocket        = "/run/mcp-gateway/opa.sock"
	DefaultStateDir         = "/var/lib/mcp-gateway"
	DefaultControl          = "/run/mcp-gateway/control.sock"
	// DefaultCredentialsDir holds backend secrets named by bare credential
	// entries; readable by root only (systemd reads them, not the gateway).
	DefaultCredentialsDir = "/etc/mcp-gateway/credentials"
)

// Gateway is the main configuration file.
type Gateway struct {
	// Socket is the unix socket local clients connect to.
	Socket string `yaml:"socket"`
	// SocketGroup, if set, owns the socket (mode 0660).
	SocketGroup string `yaml:"socket_group"`
	// HTTP configures the remote Streamable HTTP transport. Disabled when
	// Listen is empty.
	HTTP HTTP `yaml:"http"`
	// ServersDir holds the administrator's backend definitions, one per
	// *.yaml file; VendorServersDir those installed by packages. A file in
	// ServersDir overrides the vendor file of the same name, and an empty
	// file (or a symlink to /dev/null) masks it.
	ServersDir       string `yaml:"servers_dir"`
	VendorServersDir string `yaml:"vendor_servers_dir"`
	StateDir         string `yaml:"state_dir"`
	Policy           Policy `yaml:"policy"`
	// Supervisor configures how backend instances are started.
	Supervisor Supervisor `yaml:"supervisor"`
	// ApprovalTimeout bounds how long a call waits for a human decision.
	ApprovalTimeout time.Duration `yaml:"approval_timeout"`
	// Approvals configures URL and out-of-band approvals.
	Approvals Approvals `yaml:"approvals"`
	// Audit configures the audit trail.
	Audit Audit `yaml:"audit"`
}

// Audit configures the audit trail (docs/architecture.md, section 5.9).
type Audit struct {
	// Kernel is "auto" (send security-relevant events to the kernel audit
	// subsystem if possible), "on" (fail to start if not possible) or
	// "off".
	Kernel string `yaml:"kernel"`
}

// Approvals configures the control API and approval channels
// (docs/architecture.md, section 5.6).
type Approvals struct {
	// ControlSocket serves the control API (approvals, grants) to local
	// users, identified by peer credentials; e.g. the Cockpit page. "-"
	// disables it, and with it the url and oob channels.
	ControlSocket string `yaml:"control_socket"`
	// URLTemplate is the approval page URL, with "{id}" for the approval
	// id, sent to clients in URL-mode elicitations. Empty disables the url
	// channel.
	URLTemplate string `yaml:"url_template"`
}

// Supervisor configures backend instance launching.
type Supervisor struct {
	// Mode is "systemd" (transient units, confined; the default) or "exec"
	// (plain child processes, unconfined; development only).
	Mode string `yaml:"mode"`
	// SELinux is "auto" (use SELinuxContext= when SELinux is enabled),
	// "on" or "off".
	SELinux string `yaml:"selinux"`
	// IdleTimeout stops an instance this long after its last session
	// ended.
	IdleTimeout time.Duration `yaml:"idle_timeout"`
}

// HTTP configures the remote transport (MCP Streamable HTTP with OAuth
// bearer tokens; docs/architecture.md, sections 5.1, 5.2 and 7.2).
type HTTP struct {
	Listen   string `yaml:"listen"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// Issuer and Audience are used to validate bearer tokens. Audience is
	// the gateway's public MCP URL (RFC 8707 resource indicator), e.g.
	// https://gw.example.com:8443/mcp.
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	// JWKSURL overrides the key set URL found by OIDC discovery at
	// <issuer>/.well-known/openid-configuration.
	JWKSURL string `yaml:"jwks_url"`
	// GroupsClaim names the token claim holding the principal's groups.
	GroupsClaim string `yaml:"groups_claim"`
	// LocalUserClaim, if set, names a claim whose value is looked up as a
	// local account; if it exists, the principal runs as that account
	// (decision D1). Otherwise backends run as a dynamic user.
	LocalUserClaim string `yaml:"local_user_claim"`
	// Scopes that every token must carry (space-separated "scope" claim).
	Scopes []string `yaml:"scopes"`
	// AllowedOrigins lists the Origin header values accepted from browser
	// clients; requests with any other Origin are refused (DNS rebinding
	// protection). Requests without Origin are accepted.
	AllowedOrigins []string `yaml:"allowed_origins"`
	// SessionIdleTimeout closes MCP sessions without traffic.
	SessionIdleTimeout time.Duration `yaml:"session_idle_timeout"`
	// ClientCAFile holds the CA certificates (PEM) that client
	// certificates must chain to (mTLS).
	ClientCAFile string `yaml:"client_ca_file"`
	// ClientAuth is "none", "optional" (verify a client certificate if
	// one is presented) or "required". Default: "optional" with a
	// client_ca_file, else "none".
	ClientAuth string `yaml:"client_auth"`
	// RequireBoundTokens refuses bearer tokens that are not bound to the
	// client certificate (RFC 8705 cnf/x5t#S256).
	RequireBoundTokens bool `yaml:"require_bound_tokens"`
}

// Policy configures the connection to the policy decision point.
type Policy struct {
	OPASocket string        `yaml:"opa_socket"`
	Timeout   time.Duration `yaml:"timeout"`
	// WatchInterval is how often the gateway checks whether OPA loaded a
	// changed policy, to tell clients to list tools etc. again.
	WatchInterval time.Duration `yaml:"watch_interval"`
}

// Backend is one MCP server definition from the registry.
type Backend struct {
	Name        string            `yaml:"name"`
	Command     []string          `yaml:"command"`
	SELinuxType string            `yaml:"selinux_type"`
	Isolation   Isolation         `yaml:"isolation"`
	Network     bool              `yaml:"network"`
	RunAs       string            `yaml:"run_as"`
	Env         map[string]string `yaml:"env"`
	// Credentials are secrets handed to the backend by systemd
	// (LoadCredential=): "name" reads DefaultCredentialsDir/name,
	// "name:/path" reads /path. The backend finds each as
	// $CREDENTIALS_DIRECTORY/name; the gateway itself never reads them.
	Credentials []string `yaml:"credentials"`
	Sandbox     Sandbox  `yaml:"sandbox"`
}

// Credential is a parsed credentials entry.
type Credential struct {
	Name string
	Path string
}

var credentialName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

// ParseCredentials parses b.Credentials.
func (b *Backend) ParseCredentials() ([]Credential, error) {
	out := make([]Credential, 0, len(b.Credentials))
	seen := map[string]bool{}
	for _, e := range b.Credentials {
		name, path, hasPath := strings.Cut(e, ":")
		if !hasPath {
			path = filepath.Join(DefaultCredentialsDir, name)
		}
		if !credentialName.MatchString(name) {
			return nil, fmt.Errorf("credentials: invalid name %q", name)
		}
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, fmt.Errorf("credentials: %s: path must be absolute and clean, got %q", name, path)
		}
		if seen[name] {
			return nil, fmt.Errorf("credentials: duplicate name %q", name)
		}
		seen[name] = true
		out = append(out, Credential{Name: name, Path: path})
	}
	return out, nil
}

// Isolation selects how backend instances are shared.
type Isolation string

const (
	// IsolationPrincipal runs one instance per (principal, backend).
	IsolationPrincipal Isolation = "principal"
	// IsolationSession runs one instance per client session.
	IsolationSession Isolation = "session"
)

// Sandbox holds per-backend relaxations of the default systemd sandbox.
type Sandbox struct {
	// ProtectHome is "yes", "read-only" or "read-write" (i.e. no
	// protection); default "read-only".
	ProtectHome string `yaml:"protect_home"`
}

// Defaults applied to empty fields.
const (
	DefaultPolicyTimeout   = 250 * time.Millisecond
	DefaultApprovalTimeout = 120 * time.Second
	DefaultIdleTimeout     = 15 * time.Minute
	DefaultWatchInterval   = 10 * time.Second
	DefaultHTTPSessionIdle = 30 * time.Minute
	DefaultGroupsClaim     = "groups"
	DefaultSELinuxType     = "mcpsrv_generic_t"
	DefaultRunAs           = "principal"
	DefaultProtectHome     = "read-only"
)

var (
	backendName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	selinuxType = regexp.MustCompile(`^mcpsrv_[a-z0-9_]+_t$`)
)

// LoadGateway reads and validates the gateway configuration at path.
func LoadGateway(path string) (*Gateway, error) {
	g := &Gateway{}
	if err := decodeFile(path, g); err != nil {
		return nil, err
	}
	g.setDefaults()
	if err := g.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return g, nil
}

// Resolve loads the configuration: from explicit if given (it must
// exist), else from the first of DefaultConfigPath (administrator) and
// DefaultVendorConfigPath (package default) that exists, else the built-in
// defaults. It returns the path used ("" for built-in defaults).
func Resolve(explicit string) (*Gateway, string, error) {
	if explicit != "" {
		g, err := LoadGateway(explicit)
		return g, explicit, err
	}
	for _, p := range []string{DefaultConfigPath, DefaultVendorConfigPath} {
		if _, err := os.Stat(p); err == nil {
			g, err := LoadGateway(p)
			return g, p, err
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, p, err
		}
	}
	g := &Gateway{}
	g.setDefaults()
	return g, "", g.Validate()
}

func (g *Gateway) setDefaults() {
	if g.Socket == "" {
		g.Socket = DefaultSocket
	}
	if g.ServersDir == "" {
		g.ServersDir = DefaultServersDir
	}
	if g.VendorServersDir == "" {
		g.VendorServersDir = DefaultVendorServersDir
	}
	if g.StateDir == "" {
		g.StateDir = DefaultStateDir
	}
	if g.Policy.OPASocket == "" {
		g.Policy.OPASocket = DefaultOPASocket
	}
	if g.Policy.Timeout == 0 {
		g.Policy.Timeout = DefaultPolicyTimeout
	}
	if g.Policy.WatchInterval == 0 {
		g.Policy.WatchInterval = DefaultWatchInterval
	}
	if g.Supervisor.Mode == "" {
		g.Supervisor.Mode = "systemd"
	}
	if g.Supervisor.SELinux == "" {
		g.Supervisor.SELinux = "auto"
	}
	if g.ApprovalTimeout == 0 {
		g.ApprovalTimeout = DefaultApprovalTimeout
	}
	if g.Supervisor.IdleTimeout == 0 {
		g.Supervisor.IdleTimeout = DefaultIdleTimeout
	}
	if g.Approvals.ControlSocket == "" {
		g.Approvals.ControlSocket = DefaultControl
	}
	if g.Audit.Kernel == "" {
		g.Audit.Kernel = "auto"
	}
	if g.HTTP.GroupsClaim == "" {
		g.HTTP.GroupsClaim = DefaultGroupsClaim
	}
	if g.HTTP.SessionIdleTimeout == 0 {
		g.HTTP.SessionIdleTimeout = DefaultHTTPSessionIdle
	}
	if g.HTTP.ClientAuth == "" {
		g.HTTP.ClientAuth = "none"
		if g.HTTP.ClientCAFile != "" {
			g.HTTP.ClientAuth = "optional"
		}
	}
}

// Validate checks the configuration for consistency.
func (g *Gateway) Validate() error {
	if !filepath.IsAbs(g.Socket) {
		return fmt.Errorf("socket: must be an absolute path, got %q", g.Socket)
	}
	if g.Policy.Timeout < 0 {
		return errors.New("policy.timeout: must not be negative")
	}
	if g.Policy.WatchInterval < time.Second {
		return errors.New("policy.watch_interval: must be at least 1s")
	}
	if g.ApprovalTimeout < 0 {
		return errors.New("approval_timeout: must not be negative")
	}
	if g.Approvals.ControlSocket != "-" && !filepath.IsAbs(g.Approvals.ControlSocket) {
		return fmt.Errorf("approvals.control_socket: must be an absolute path or \"-\", got %q", g.Approvals.ControlSocket)
	}
	if t := g.Approvals.URLTemplate; t != "" {
		if !strings.Contains(t, "{id}") {
			return errors.New("approvals.url_template: must contain {id}")
		}
		if err := checkURL(strings.ReplaceAll(t, "{id}", "x")); err != nil {
			return fmt.Errorf("approvals.url_template: %w", err)
		}
	}
	if g.Supervisor.IdleTimeout < 0 {
		return errors.New("supervisor.idle_timeout: must not be negative")
	}
	switch g.Supervisor.Mode {
	case "systemd", "exec":
	default:
		return fmt.Errorf("supervisor.mode: unknown value %q", g.Supervisor.Mode)
	}
	switch g.Supervisor.SELinux {
	case "auto", "on", "off":
	default:
		return fmt.Errorf("supervisor.selinux: unknown value %q", g.Supervisor.SELinux)
	}
	switch g.Audit.Kernel {
	case "auto", "on", "off":
	default:
		return fmt.Errorf("audit.kernel: unknown value %q", g.Audit.Kernel)
	}
	if g.HTTP.Listen != "" {
		if g.HTTP.CertFile == "" || g.HTTP.KeyFile == "" {
			return errors.New("http: cert_file and key_file are required when listen is set")
		}
		if g.HTTP.Issuer == "" || g.HTTP.Audience == "" {
			return errors.New("http: issuer and audience are required when listen is set")
		}
		switch g.HTTP.ClientAuth {
		case "none":
			if g.HTTP.RequireBoundTokens {
				return errors.New("http.require_bound_tokens: needs client certificates (client_auth)")
			}
		case "optional", "required":
			if g.HTTP.ClientCAFile == "" {
				return fmt.Errorf("http.client_auth %s: client_ca_file is required", g.HTTP.ClientAuth)
			}
		default:
			return fmt.Errorf("http.client_auth: unknown value %q", g.HTTP.ClientAuth)
		}
		for name, v := range map[string]string{"issuer": g.HTTP.Issuer, "audience": g.HTTP.Audience, "jwks_url": g.HTTP.JWKSURL} {
			if v == "" && name == "jwks_url" {
				continue
			}
			if err := checkURL(v); err != nil {
				return fmt.Errorf("http.%s: %w", name, err)
			}
		}
		if g.HTTP.SessionIdleTimeout < 0 {
			return errors.New("http.session_idle_timeout: must not be negative")
		}
	}
	return nil
}

// checkURL accepts https URLs, and http URLs on loopback hosts (for
// development and tests).
func checkURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if u.Host == "" {
		return fmt.Errorf("%q is not an absolute URL", s)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if h := u.Hostname(); h == "localhost" || net.ParseIP(h).IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("%q must be an https URL (http only on loopback)", s)
}

// LoadBackends reads the *.yaml files of dirs (missing dirs are skipped)
// and returns the validated backend definitions keyed by backend name. A
// file in a later dir overrides the file with the same name in an earlier
// one; an empty file, or a symlink to /dev/null, masks it (as with systemd
// units). Pass the vendor dir first, the administrator's last.
func LoadBackends(dirs ...string) (map[string]*Backend, error) {
	byFile := map[string]string{}
	for _, dir := range dirs {
		paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			return nil, err
		}
		for _, p := range paths {
			byFile[filepath.Base(p)] = p
		}
	}
	var paths []string
	for _, p := range byFile {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if fi.Size() == 0 { // masked (empty file or /dev/null)
			continue
		}
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool { return filepath.Base(paths[i]) < filepath.Base(paths[j]) })
	backends := make(map[string]*Backend, len(paths))
	for _, p := range paths {
		b := &Backend{}
		if err := decodeFile(p, b); err != nil {
			return nil, err
		}
		b.setDefaults()
		if err := b.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if _, dup := backends[b.Name]; dup {
			return nil, fmt.Errorf("%s: duplicate backend name %q", p, b.Name)
		}
		backends[b.Name] = b
	}
	return backends, nil
}

func (b *Backend) setDefaults() {
	if b.SELinuxType == "" {
		b.SELinuxType = DefaultSELinuxType
	}
	if b.Isolation == "" {
		b.Isolation = IsolationPrincipal
	}
	if b.RunAs == "" {
		b.RunAs = DefaultRunAs
	}
	if b.Sandbox.ProtectHome == "" {
		b.Sandbox.ProtectHome = DefaultProtectHome
	}
}

// Validate checks a backend definition.
func (b *Backend) Validate() error {
	if !backendName.MatchString(b.Name) {
		return fmt.Errorf("name: %q must match %s", b.Name, backendName)
	}
	if len(b.Command) == 0 || !filepath.IsAbs(b.Command[0]) {
		return errors.New("command: must be non-empty and start with an absolute path")
	}
	if !selinuxType.MatchString(b.SELinuxType) {
		return fmt.Errorf("selinux_type: %q must match %s", b.SELinuxType, selinuxType)
	}
	switch b.Isolation {
	case IsolationPrincipal, IsolationSession:
	default:
		return fmt.Errorf("isolation: unknown value %q", b.Isolation)
	}
	switch b.Sandbox.ProtectHome {
	case "yes", "read-only", "read-write":
	default:
		return fmt.Errorf("sandbox.protect_home: unknown value %q", b.Sandbox.ProtectHome)
	}
	if _, err := b.ParseCredentials(); err != nil {
		return err
	}
	return nil
}

func decodeFile(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}
