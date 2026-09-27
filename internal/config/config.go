// Package config loads the gateway configuration and the backend registry.
//
// See docs/architecture.md, sections 5.1, 5.5 and 5.7.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// Default paths.
const (
	DefaultConfigPath = "/etc/mcp-gateway/gateway.yaml"
	DefaultServersDir = "/etc/mcp-gateway/servers.d"
	DefaultSocket     = "/run/mcp-gateway/mcp.sock"
	DefaultOPASocket  = "/run/mcp-gateway/opa.sock"
	DefaultStateDir   = "/var/lib/mcp-gateway"
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
	// ServersDir holds one backend definition per *.yaml file.
	ServersDir string `yaml:"servers_dir"`
	StateDir   string `yaml:"state_dir"`
	Policy     Policy `yaml:"policy"`
	// Supervisor configures how backend instances are started.
	Supervisor Supervisor `yaml:"supervisor"`
	// ApprovalTimeout bounds how long a call waits for a human decision.
	ApprovalTimeout time.Duration `yaml:"approval_timeout"`
}

// Supervisor configures backend instance launching.
type Supervisor struct {
	// Mode is "systemd" (transient units, confined; the default) or "exec"
	// (plain child processes, unconfined; development only).
	Mode string `yaml:"mode"`
	// SELinux is "auto" (use SELinuxContext= when SELinux is enabled),
	// "on" or "off".
	SELinux string `yaml:"selinux"`
}

// HTTP configures the remote transport.
type HTTP struct {
	Listen   string `yaml:"listen"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// Issuer and Audience are used to validate bearer tokens. Audience is
	// the gateway's public MCP URL (RFC 8707 resource indicator).
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
}

// Policy configures the connection to the policy decision point.
type Policy struct {
	OPASocket string        `yaml:"opa_socket"`
	Timeout   time.Duration `yaml:"timeout"`
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
	Credentials []string          `yaml:"credentials"`
	Sandbox     Sandbox           `yaml:"sandbox"`
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

func (g *Gateway) setDefaults() {
	if g.Socket == "" {
		g.Socket = DefaultSocket
	}
	if g.ServersDir == "" {
		g.ServersDir = DefaultServersDir
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
	if g.Supervisor.Mode == "" {
		g.Supervisor.Mode = "systemd"
	}
	if g.Supervisor.SELinux == "" {
		g.Supervisor.SELinux = "auto"
	}
	if g.ApprovalTimeout == 0 {
		g.ApprovalTimeout = DefaultApprovalTimeout
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
	if g.ApprovalTimeout < 0 {
		return errors.New("approval_timeout: must not be negative")
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
	if g.HTTP.Listen != "" {
		if g.HTTP.CertFile == "" || g.HTTP.KeyFile == "" {
			return errors.New("http: cert_file and key_file are required when listen is set")
		}
		if g.HTTP.Issuer == "" || g.HTTP.Audience == "" {
			return errors.New("http: issuer and audience are required when listen is set")
		}
	}
	return nil
}

// LoadBackends reads every *.yaml file in dir, sorted by name, and returns
// the validated backend definitions keyed by backend name.
func LoadBackends(dir string) (map[string]*Backend, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
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
