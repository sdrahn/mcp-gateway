package config

import (
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"time"
)

// Kubernetes configures the Kubernetes launcher (supervisor.mode:
// kubernetes; docs/architecture.md, section 5.12.3): instances of stdio
// servers as pods of their own in Namespace; servers that speak HTTP keep
// their connectors as child processes of the gateway.
type Kubernetes struct {
	// Namespace is where instances run: one of their own, in which the
	// gateway's ServiceAccount may create and delete pods, Secrets and
	// NetworkPolicies.
	Namespace string `yaml:"namespace"`
	// BridgeImage is the gateway's own image, which carries
	// mcp-stdio-bridge (an init container copies it into each pod).
	BridgeImage string `yaml:"bridge_image"`
	// ImagePullPolicy of the instances' containers: IfNotPresent (the
	// default), Always or Never.
	ImagePullPolicy string `yaml:"image_pull_policy"`
	// GatewayNamespace and GatewayLabels select the gateway's pods: the
	// only ones an instance's NetworkPolicy lets reach its bridge.
	GatewayNamespace string            `yaml:"gateway_namespace"`
	GatewayLabels    map[string]string `yaml:"gateway_labels"`
	// StartTimeout bounds how long a pod may take to run (scheduling,
	// the image pull); default 2m.
	StartTimeout time.Duration `yaml:"start_timeout"`
	// SELinux "on" gives each instance an MCS level of its own from
	// supervisor.mcs_range (for nodes that run SELinux); "off" (the
	// default) none.
	SELinux string `yaml:"selinux"`
	// AllowSELinuxType passes a definition's selinux_type to its pod:
	// the nodes' policy must have the type.
	AllowSELinuxType bool `yaml:"allow_selinux_type"`
	// APIServer, TokenFile and CAFile reach the Kubernetes API as the
	// gateway's ServiceAccount: by default the in-cluster address, the
	// pod's projected token and the cluster's CA as the manifests mount
	// them.
	APIServer string `yaml:"api_server"`
	TokenFile string `yaml:"token_file"`
	CAFile    string `yaml:"ca_file"`
}

// dnsLabel is a namespace's name (RFC 1123 label).
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// Defaults of the Kubernetes launcher.
const (
	DefaultKubernetesAPIServer = "https://kubernetes.default.svc"
	DefaultKubernetesTokenFile = "/var/run/secrets/mcp-gateway/token/token"
	DefaultKubernetesCAFile    = "/etc/mcp-gateway/cluster-ca/ca.crt"
	DefaultPodStartTimeout     = 2 * time.Minute
)

// WithDefaults returns k with its defaults filled in.
func (k Kubernetes) WithDefaults() Kubernetes {
	if k.ImagePullPolicy == "" {
		k.ImagePullPolicy = "IfNotPresent"
	}
	if k.StartTimeout == 0 {
		k.StartTimeout = DefaultPodStartTimeout
	}
	if k.SELinux == "" {
		k.SELinux = "off"
	}
	if k.APIServer == "" {
		k.APIServer = DefaultKubernetesAPIServer
	}
	if k.TokenFile == "" {
		k.TokenFile = DefaultKubernetesTokenFile
	}
	if k.CAFile == "" {
		k.CAFile = DefaultKubernetesCAFile
	}
	return k
}

func (k Kubernetes) validate(container bool) error {
	if !container {
		return errors.New("supervisor.mode: kubernetes only in container mode (deployment: container)")
	}
	k = k.WithDefaults()
	var errs []error
	need := func(key, v string) {
		if v == "" {
			errs = append(errs, fmt.Errorf("supervisor.kubernetes.%s: required with supervisor.mode: kubernetes", key))
		}
	}
	need("namespace", k.Namespace)
	need("bridge_image", k.BridgeImage)
	need("gateway_namespace", k.GatewayNamespace)
	if len(k.GatewayLabels) == 0 {
		errs = append(errs, errors.New("supervisor.kubernetes.gateway_labels: required with supervisor.mode: kubernetes (the labels of the gateway's pods, the only ones that may reach an instance)"))
	}
	for _, key := range slices.Sorted(maps.Keys(k.GatewayLabels)) {
		if !labelKey.MatchString(key) || !labelValue.MatchString(k.GatewayLabels[key]) {
			errs = append(errs, fmt.Errorf("supervisor.kubernetes.gateway_labels: %q: %q is not a label", key, k.GatewayLabels[key]))
		}
	}
	for key, v := range map[string]string{"namespace": k.Namespace, "gateway_namespace": k.GatewayNamespace} {
		if v != "" && !dnsLabel.MatchString(v) {
			errs = append(errs, fmt.Errorf("supervisor.kubernetes.%s: %q is not a namespace name", key, v))
		}
	}
	if k.BridgeImage != "" && !image.MatchString(k.BridgeImage) {
		errs = append(errs, fmt.Errorf("supervisor.kubernetes.bridge_image: %q is not an image reference", k.BridgeImage))
	}
	switch k.ImagePullPolicy {
	case "IfNotPresent", "Always", "Never":
	default:
		errs = append(errs, fmt.Errorf("supervisor.kubernetes.image_pull_policy: %q (IfNotPresent, Always or Never)", k.ImagePullPolicy))
	}
	switch k.SELinux {
	case "on", "off":
	default:
		errs = append(errs, fmt.Errorf("supervisor.kubernetes.selinux: %q (on or off)", k.SELinux))
	}
	if k.StartTimeout < 10*time.Second || k.StartTimeout > time.Hour {
		errs = append(errs, errors.New("supervisor.kubernetes.start_timeout: between 10s and 1h"))
	}
	if err := checkURL(k.APIServer); err != nil {
		errs = append(errs, fmt.Errorf("supervisor.kubernetes.api_server: %w", err))
	}
	for key, v := range map[string]string{"token_file": k.TokenFile, "ca_file": k.CAFile} {
		if !filepath.IsAbs(v) {
			errs = append(errs, fmt.Errorf("supervisor.kubernetes.%s: must be an absolute path, got %q", key, v))
		}
	}
	return errors.Join(errs...)
}

// KubernetesLauncher reports whether stdio servers run in pods of their
// own.
func (g *Gateway) KubernetesLauncher() bool {
	return g.Container() && g.Supervisor.Mode == "kubernetes"
}
