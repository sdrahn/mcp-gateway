package config

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ServerDiscovery configures servers discovered in the cluster
// (docs/architecture.md, section 5.12.8, D25): the Services of the named
// namespaces that carry the selector's labels become definitions of
// servers that speak HTTP, beside those of the server files. Container
// mode only.
type ServerDiscovery struct {
	// Namespaces are the namespaces whose Services are watched, each with
	// the prefix of its servers' names. None: no discovery.
	Namespaces []DiscoveryNamespace `yaml:"namespaces"`
	// Selector selects the Services (DefaultDiscoverySelector): label
	// equalities, inequalities and existences, comma-separated.
	Selector string `yaml:"selector"`
	// APIServer, TokenFile and CAFile reach the Kubernetes API as the
	// gateway's ServiceAccount, with the defaults of
	// supervisor.kubernetes.
	APIServer string `yaml:"api_server"`
	TokenFile string `yaml:"token_file"`
	CAFile    string `yaml:"ca_file"`
}

// DiscoveryNamespace is a namespace whose Services are discovered.
type DiscoveryNamespace struct {
	Namespace string `yaml:"namespace"`
	// Prefix starts the names of its servers: "<namespace>-" when unset,
	// "" only when set so (prefix: ""), which lets a Service take any
	// name the role data may already grant.
	Prefix *string `yaml:"prefix"`
}

// DefaultDiscoverySelector is the label a Service carries to be
// discovered.
const DefaultDiscoverySelector = "mcp-gateway.io/server=true"

// The annotations of a discovered Service: the server's name (without the
// prefix; the Service's name by default), the port (a name or a number;
// by default the port named mcp, else the only one) and the path
// (DefaultDiscoveryPath).
const (
	DiscoveryNameAnnotation = "mcp-gateway.io/name"
	DiscoveryPortAnnotation = "mcp-gateway.io/port"
	DiscoveryPathAnnotation = "mcp-gateway.io/path"
	DefaultDiscoveryPath    = "/mcp"
)

// Enabled reports whether servers are discovered.
func (d ServerDiscovery) Enabled() bool { return len(d.Namespaces) > 0 }

// WithDefaults returns d with its defaults filled in.
func (d ServerDiscovery) WithDefaults() ServerDiscovery {
	if d.Selector == "" {
		d.Selector = DefaultDiscoverySelector
	}
	if d.APIServer == "" {
		d.APIServer = DefaultKubernetesAPIServer
	}
	if d.TokenFile == "" {
		d.TokenFile = DefaultKubernetesTokenFile
	}
	if d.CAFile == "" {
		d.CAFile = DefaultKubernetesCAFile
	}
	return d
}

// PrefixOf returns the prefix of a namespace's servers.
func (n DiscoveryNamespace) PrefixOf() string {
	if n.Prefix != nil {
		return *n.Prefix
	}
	return n.Namespace + "-"
}

// selectorTerm is a term of a label selector: key, key=value, key==value,
// key!=value or !key, with a key of a label (an optional DNS prefix and
// a name) and a label value.
var selectorTerm = regexp.MustCompile(`^(!?)((?:[a-z0-9]([-a-z0-9.]*[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?)(?:(=|==|!=)([A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?)?)?$`)

// prefixPattern is what a prefix may be: the start of a server's name.
var prefixPattern = regexp.MustCompile(`^([a-z][a-z0-9-]{0,30})?$`)

func (d ServerDiscovery) validate(container bool) error {
	if !d.Enabled() {
		if d.Selector != "" || d.APIServer != "" || d.TokenFile != "" || d.CAFile != "" {
			return errors.New("server_discovery: set namespaces, or nothing")
		}
		return nil
	}
	if !container {
		return errors.New("server_discovery: only in container mode (deployment: container)")
	}
	seen := map[string]bool{}
	prefixes := map[string]string{}
	for i, n := range d.Namespaces {
		if !dnsLabel.MatchString(n.Namespace) {
			return fmt.Errorf("server_discovery.namespaces[%d].namespace: %q is not a namespace name", i, n.Namespace)
		}
		if seen[n.Namespace] {
			return fmt.Errorf("server_discovery.namespaces: %s twice", n.Namespace)
		}
		seen[n.Namespace] = true
		p := n.PrefixOf()
		if !prefixPattern.MatchString(p) {
			return fmt.Errorf("server_discovery.namespaces[%d].prefix: %q is not the start of a server's name (%s)", i, p, backendName)
		}
		if other, ok := prefixes[p]; ok {
			return fmt.Errorf("server_discovery.namespaces: %s and %s have the same prefix %q: their servers' names would collide", other, n.Namespace, p)
		}
		prefixes[p] = n.Namespace
	}
	if d.Selector != "" {
		for _, term := range strings.Split(d.Selector, ",") {
			if !selectorTerm.MatchString(strings.TrimSpace(term)) {
				return fmt.Errorf("server_discovery.selector: %q is not a label selector of equalities, inequalities and existences", d.Selector)
			}
		}
	}
	return nil
}
