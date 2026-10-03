// Package config loads the gateway configuration and the backend registry.
//
// See docs/architecture.md, sections 5.1, 5.5 and 5.7.
package config

import (
	"bytes"
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

// Version is the version of the configuration formats this gateway reads:
// gateway.yaml and server definitions. A file without a version is read
// as this version; a file of another version is refused. Compatible
// changes (new keys) keep the version; a key that goes away is deprecated
// first (see deprecation) and removed a minor release later
// (docs/architecture.md, decision D10).
const Version = 1

// Gateway is the main configuration file.
type Gateway struct {
	// Version of the file's format (Version).
	Version int `yaml:"version"`
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
	// Notifications configures the push channels for approvals.
	Notifications Notifications `yaml:"notifications"`
	// Metrics configures the metrics listener.
	Metrics Metrics `yaml:"metrics"`
	// Limits bound sessions and instances (decision D14).
	Limits Limits `yaml:"limits"`

	// Warnings are the deprecated keys the file uses (see deprecation).
	Warnings []string `yaml:"-"`
}

// Limits bound how many sessions and backend instances a principal, and
// the gateway as a whole, may have (docs/architecture.md, decision D14).
type Limits struct {
	// SessionsPerPrincipal limits a principal's open sessions (local and
	// HTTP together). At the limit, the principal's longest-idle HTTP
	// session makes room; without one, a new session is refused.
	SessionsPerPrincipal int `yaml:"sessions_per_principal"`
	// InstancesPerPrincipal limits a principal's running instances. At the
	// limit, the longest-idle instance no session uses makes room;
	// without one, the call needing a new instance fails.
	InstancesPerPrincipal int `yaml:"instances_per_principal"`
	// Instances limits the running instances of all principals; 0 (the
	// default) means no limit. Discovery instances do not count.
	Instances int `yaml:"instances"`
}

// Metrics configures where the metrics (Prometheus text format) can be
// read besides the control socket (GET /v1/metrics, root only).
type Metrics struct {
	// Listen is a host:port for plain HTTP (GET /metrics), without
	// authentication: anyone who can reach it reads the counts. Empty
	// (the default) disables it; prefer a loopback address.
	Listen string `yaml:"listen"`
}

// Notifications configures how approvers learn about pending approvals
// besides the inbox (docs/architecture.md, section 5.6.3). Desktop
// notifications need no configuration: mcp-gateway-notify follows the
// control API.
type Notifications struct {
	Email Email `yaml:"email"`
}

// Email configures e-mail notifications; enabled when SMTP is set.
type Email struct {
	// SMTP is the mail server, host:port (e.g. localhost:25).
	SMTP string `yaml:"smtp"`
	From string `yaml:"from"`
	// To is the address template for an approver's local account name,
	// "{user}" (local delivery by the MTA) or e.g. "{user}@example.com".
	To string `yaml:"to"`
	// StartTLS is "auto" (use it if offered), "always" or "never".
	StartTLS string `yaml:"starttls"`
	// Username and PasswordFile authenticate (PLAIN, over TLS or to
	// localhost). The password file is read at start (e.g. from systemd's
	// $CREDENTIALS_DIRECTORY via LoadCredential=).
	Username     string `yaml:"username"`
	PasswordFile string `yaml:"password_file"`
	// IncludeArgs puts the call's arguments into the mail; off by
	// default, since mail may leave the host.
	IncludeArgs bool `yaml:"include_args"`
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
	// ProgressInterval is how often a call waiting for approval reports
	// progress to the client, when the client asked for progress (MCP
	// clients may give up on requests that report nothing; the TypeScript
	// SDK does after 60 s).
	ProgressInterval time.Duration `yaml:"progress_interval"`
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
	// MCSRange is the category range ("cN.cM") backend instances get
	// their category pairs from. Keep it disjoint from libvirt's
	// (/usr/share/mcp-gateway/mcs drop-ins confine libvirt to c0.c767).
	MCSRange string `yaml:"mcs_range"`
	// MCSAvoid is "auto" (skip pairs held by running containers and
	// virtual machines, and replace an instance whose pair one of them
	// takes later) or "off".
	MCSAvoid string `yaml:"mcs_avoid"`
}

// MCSCategories returns the bounds of MCSRange.
func (s Supervisor) MCSCategories() (lo, hi int, err error) {
	if _, err := fmt.Sscanf(s.MCSRange, "c%d.c%d", &lo, &hi); err != nil ||
		fmt.Sprintf("c%d.c%d", lo, hi) != s.MCSRange {
		return 0, 0, fmt.Errorf("supervisor.mcs_range: want cN.cM, got %q", s.MCSRange)
	}
	if lo < 0 || hi > MaxCategory || hi-lo+1 < MinMCSCategories {
		return 0, 0, fmt.Errorf("supervisor.mcs_range: %q must lie within c0.c%d and span at least %d categories",
			s.MCSRange, MaxCategory, MinMCSCategories)
	}
	return lo, hi, nil
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
	// Version of the file's format (Version).
	Version     int       `yaml:"version"`
	Name        string    `yaml:"name"`
	Command     []string  `yaml:"command"`
	SELinuxType string    `yaml:"selinux_type"`
	Isolation   Isolation `yaml:"isolation"`
	Network     bool      `yaml:"network"`
	RunAs       string    `yaml:"run_as"`
	// Discovery is "shared" (tool, prompt and resource template lists
	// come from a gateway-owned instance without any user's identity and
	// are cached, so listing does not start instances for every user) or
	// "instance" (lists come from the principal's own instance, for
	// servers whose lists depend on the user).
	Discovery string            `yaml:"discovery"`
	Env       map[string]string `yaml:"env"`
	// Credentials are secrets handed to the backend by systemd
	// (LoadCredential=): "name" reads DefaultCredentialsDir/name,
	// "name:/path" reads /path. The backend finds each as
	// $CREDENTIALS_DIRECTORY/name; the gateway itself never reads them.
	Credentials []string `yaml:"credentials"`
	Sandbox     Sandbox  `yaml:"sandbox"`
	// Privileged runs the backend with the rights of a root system
	// service instead of the sandbox, for servers that change the system
	// as a whole (package installation). Only the administrator's
	// directory may define one, and only with run_as: root.
	Privileged bool `yaml:"privileged"`

	// Warnings are the deprecated keys the file uses (see deprecation).
	Warnings []string `yaml:"-"`
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

// Discovery modes (Backend.Discovery).
const (
	DiscoveryShared   = "shared"
	DiscoveryInstance = "instance"
)

// Sandbox holds per-backend relaxations of the default systemd sandbox.
type Sandbox struct {
	// ProtectHome is "yes", "read-only" or "read-write" (i.e. no
	// protection); default "read-only".
	ProtectHome string `yaml:"protect_home"`
	// ReadWritePaths are existing absolute paths the instance may write
	// despite ProtectSystem=strict (systemd ReadWritePaths=).
	ReadWritePaths []string `yaml:"read_write_paths"`
	// StateDirectory is a directory below /var/lib that systemd creates
	// for the instance, owned by its user and writable (StateDirectory=).
	StateDirectory string `yaml:"state_directory"`
}

// stateDirectory is a relative path of plain names, as StateDirectory=
// takes it.
var stateDirectory = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$`)

// gatewayPaths may not be made writable for instances, nor any directory
// containing one of them: the gateway's configuration, policy, secrets,
// state and sockets.
var gatewayPaths = []string{
	"/etc/mcp-gateway", "/usr/etc/mcp-gateway", "/usr/share/mcp-gateway",
	DefaultStateDir, "/run/mcp-gateway",
}

// validate checks the sandbox relaxations.
func (s *Sandbox) validate() error {
	switch s.ProtectHome {
	case "yes", "read-only", "read-write":
	default:
		return fmt.Errorf("sandbox.protect_home: unknown value %q", s.ProtectHome)
	}
	for _, p := range s.ReadWritePaths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("sandbox.read_write_paths: %q must be absolute and clean", p)
		}
		for _, g := range gatewayPaths {
			if within(p, g) || within(g, p) {
				return fmt.Errorf("sandbox.read_write_paths: %q would make the gateway's %s writable", p, g)
			}
		}
	}
	if d := s.StateDirectory; d != "" {
		if !stateDirectory.MatchString(d) || strings.Contains(d, "..") {
			return fmt.Errorf("sandbox.state_directory: %q must be a relative path of plain names, e.g. %q", d, "my-server")
		}
		if within(filepath.Join("/var/lib", d), DefaultStateDir) {
			return fmt.Errorf("sandbox.state_directory: %q is the gateway's own state directory", d)
		}
	}
	return nil
}

// within reports whether path is dir or below it.
func within(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

// Defaults applied to empty fields.
const (
	DefaultPolicyTimeout         = 250 * time.Millisecond
	DefaultApprovalTimeout       = 120 * time.Second
	DefaultProgressInterval      = 15 * time.Second
	DefaultIdleTimeout           = 15 * time.Minute
	DefaultSessionsPerPrincipal  = 64
	DefaultInstancesPerPrincipal = 32
	// DefaultMCSRange is the upper quarter of the targeted policy's
	// categories; libvirt is confined to the rest by the shipped drop-ins.
	DefaultMCSRange        = "c768.c1023"
	MaxCategory            = 1023
	MinMCSCategories       = 8
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
	warnings, err := decodeFile(path, g, gatewayDeprecations)
	if err != nil {
		return nil, err
	}
	g.Warnings = warnings
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
	if g.Version == 0 {
		g.Version = Version
	}
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
	if g.Supervisor.MCSRange == "" {
		g.Supervisor.MCSRange = DefaultMCSRange
	}
	if g.Supervisor.MCSAvoid == "" {
		g.Supervisor.MCSAvoid = "auto"
	}
	if g.Approvals.ProgressInterval == 0 {
		g.Approvals.ProgressInterval = DefaultProgressInterval
	}
	if g.ApprovalTimeout == 0 {
		g.ApprovalTimeout = DefaultApprovalTimeout
	}
	if g.Supervisor.IdleTimeout == 0 {
		g.Supervisor.IdleTimeout = DefaultIdleTimeout
	}
	if g.Limits.SessionsPerPrincipal == 0 {
		g.Limits.SessionsPerPrincipal = DefaultSessionsPerPrincipal
	}
	if g.Limits.InstancesPerPrincipal == 0 {
		g.Limits.InstancesPerPrincipal = DefaultInstancesPerPrincipal
	}
	if g.Approvals.ControlSocket == "" {
		g.Approvals.ControlSocket = DefaultControl
	}
	if g.Audit.Kernel == "" {
		g.Audit.Kernel = "auto"
	}
	if g.Notifications.Email.To == "" {
		g.Notifications.Email.To = "{user}"
	}
	if g.Notifications.Email.StartTLS == "" {
		g.Notifications.Email.StartTLS = "auto"
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
	if err := checkVersion(g.Version); err != nil {
		return err
	}
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
	if g.Approvals.ProgressInterval < time.Second {
		return errors.New("approvals.progress_interval: must be at least 1s")
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
	if _, _, err := g.Supervisor.MCSCategories(); err != nil {
		return err
	}
	switch g.Supervisor.MCSAvoid {
	case "auto", "off":
	default:
		return fmt.Errorf("supervisor.mcs_avoid: unknown value %q", g.Supervisor.MCSAvoid)
	}
	switch g.Audit.Kernel {
	case "auto", "on", "off":
	default:
		return fmt.Errorf("audit.kernel: unknown value %q", g.Audit.Kernel)
	}
	if e := g.Notifications.Email; e.SMTP != "" {
		if _, _, err := net.SplitHostPort(e.SMTP); err != nil {
			return fmt.Errorf("notifications.email.smtp: want host:port, got %q", e.SMTP)
		}
		if e.From == "" {
			return errors.New("notifications.email.from: required with smtp")
		}
		switch e.StartTLS {
		case "auto", "always", "never":
		default:
			return fmt.Errorf("notifications.email.starttls: unknown value %q", e.StartTLS)
		}
		if (e.Username == "") != (e.PasswordFile == "") {
			return errors.New("notifications.email: username and password_file go together")
		}
	}
	if g.Limits.SessionsPerPrincipal < 0 || g.Limits.InstancesPerPrincipal < 0 || g.Limits.Instances < 0 {
		return errors.New("limits: must not be negative")
	}
	if l := g.Metrics.Listen; l != "" {
		if _, port, err := net.SplitHostPort(l); err != nil || port == "" {
			return fmt.Errorf("metrics.listen: want host:port, got %q", l)
		}
		if l == g.HTTP.Listen {
			return errors.New("metrics.listen: must differ from http.listen")
		}
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
// units). Pass the vendor dir first, the administrator's last: only the
// last dir may define privileged backends.
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
	from := make(map[string]string, len(paths)) // backend name to file
	for _, p := range paths {
		b := &Backend{}
		warnings, err := decodeFile(p, b, backendDeprecations)
		if err != nil {
			return nil, err
		}
		b.Warnings = append(warnings, b.deprecatedProgram()...)
		b.setDefaults()
		if err := b.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if b.Privileged && (len(dirs) == 0 || filepath.Dir(p) != filepath.Clean(dirs[len(dirs)-1])) {
			return nil, fmt.Errorf("%s: privileged: only allowed in %s", p, dirs[len(dirs)-1])
		}
		if first, dup := from[b.Name]; dup {
			return nil, duplicateName(b.Name, first, p, dirs)
		}
		backends[b.Name] = b
		from[b.Name] = p
	}
	return backends, nil
}

// deprecatedPrograms are program names a package keeps for a minor
// release as links to the program that replaces them; definitions naming
// one get a warning.
var deprecatedPrograms = map[string]deprecation{
	"mcp-fs-demo": {Key: "command: mcp-fs-demo", Since: "0.5", Use: "name mcp-server-fs, in the same directory, which it links to"},
}

func (b *Backend) deprecatedProgram() []string {
	if len(b.Command) == 0 {
		return nil
	}
	if d, ok := deprecatedPrograms[filepath.Base(b.Command[0])]; ok {
		return []string{d.warning()}
	}
	return nil
}

// duplicateName explains two files defining the same server. A file in
// the administrator's directory replaces a package's file only under the
// same file name, not the same server name: the usual cause is a
// hand-made definition from before a setup package shipped one.
func duplicateName(name, a, b string, dirs []string) error {
	admin := ""
	if len(dirs) > 1 {
		admin = filepath.Clean(dirs[len(dirs)-1])
	}
	mine, theirs := a, b
	if filepath.Dir(a) != admin {
		mine, theirs = b, a
	}
	if admin == "" || filepath.Dir(mine) != admin || filepath.Dir(theirs) == admin {
		return fmt.Errorf("server %q is defined twice, in %s and %s: remove or rename one", name, a, b)
	}
	return fmt.Errorf("server %q is defined twice, in %s and in %s (a package's); a file in %s replaces a package's file "+
		"only under the same file name: rename yours to %s to replace it, or remove it",
		name, mine, theirs, admin, filepath.Join(admin, filepath.Base(theirs)))
}

// ApplyDefaults fills in the defaults of a definition built in code (a
// file's are filled in by LoadBackends).
func (b *Backend) ApplyDefaults() { b.setDefaults() }

func (b *Backend) setDefaults() {
	if b.Version == 0 {
		b.Version = Version
	}
	if b.SELinuxType == "" {
		b.SELinuxType = DefaultSELinuxType
	}
	if b.Isolation == "" {
		b.Isolation = IsolationPrincipal
	}
	if b.RunAs == "" {
		b.RunAs = DefaultRunAs
	}
	if b.Discovery == "" {
		b.Discovery = DiscoveryShared
	}
	if b.Sandbox.ProtectHome == "" {
		b.Sandbox.ProtectHome = DefaultProtectHome
	}
}

// Validate checks a backend definition.
func (b *Backend) Validate() error {
	if err := checkVersion(b.Version); err != nil {
		return err
	}
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
	switch b.Discovery {
	case DiscoveryShared, DiscoveryInstance:
	default:
		return fmt.Errorf("discovery: unknown value %q", b.Discovery)
	}
	if err := b.Sandbox.validate(); err != nil {
		return err
	}
	if b.Privileged {
		if b.RunAs != "root" {
			return fmt.Errorf("privileged: needs run_as: root, not %q", b.RunAs)
		}
		if len(b.Sandbox.ReadWritePaths) > 0 {
			return errors.New("sandbox.read_write_paths: has no effect on a privileged backend, which may write everywhere")
		}
	}
	if _, err := b.ParseCredentials(); err != nil {
		return err
	}
	return nil
}

// checkVersion accepts the format version this gateway reads.
func checkVersion(v int) error {
	switch {
	case v == Version:
		return nil
	case v > Version:
		return fmt.Errorf("version: %d is newer than this gateway reads (%d); update mcp-gateway", v, Version)
	}
	return fmt.Errorf("version: %d is not supported (this gateway reads %d)", v, Version)
}

// deprecation is a key that is still read, but goes away a minor release
// after the one that deprecated it (docs/architecture.md, decision D10).
// Its field stays in the struct until then, and setDefaults moves its
// value to the replacement.
type deprecation struct {
	Key   string // dotted path, e.g. "supervisor.mode"
	Since string // the release that deprecated it, e.g. "0.4"
	Use   string // what to write instead
}

// The deprecated keys of gateway.yaml and of server definitions.
var gatewayDeprecations, backendDeprecations []deprecation

func (d deprecation) warning() string {
	return fmt.Sprintf("%s is deprecated since %s and will be removed in the next minor release: %s", d.Key, d.Since, d.Use)
}

// decodeFile decodes the YAML file at path into v, refusing unknown keys,
// and returns a warning for each deprecated key the file uses.
func decodeFile(path string, v any, deprecated []deprecation) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(deprecated) == 0 {
		return nil, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var warnings []string
	for _, d := range deprecated {
		if hasKey(&doc, strings.Split(d.Key, ".")) {
			warnings = append(warnings, d.warning())
		}
	}
	return warnings, nil
}

// hasKey reports whether the mapping path exists in the YAML document n.
func hasKey(n *yaml.Node, path []string) bool {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		n = n.Content[0]
	}
	if len(path) == 0 {
		return true
	}
	if n.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == path[0] {
			return hasKey(n.Content[i+1], path[1:])
		}
	}
	return false
}
