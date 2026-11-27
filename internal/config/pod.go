package config

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// Resources are a pod's requests and limits, as Kubernetes writes them
// ("500m", "256Mi").
type Resources struct {
	Requests map[string]string `yaml:"requests"`
	Limits   map[string]string `yaml:"limits"`
}

// Toleration lets an instance's pod onto nodes with a taint.
type Toleration struct {
	Key               string `yaml:"key"`
	Operator          string `yaml:"operator"`
	Value             string `yaml:"value"`
	Effect            string `yaml:"effect"`
	TolerationSeconds *int64 `yaml:"toleration_seconds"`
}

// resourceNames are the resources a definition may request and limit.
var resourceNames = []string{"cpu", "memory", "ephemeral-storage"}

// quantity is a Kubernetes quantity in the forms definitions need: a
// number with a decimal or binary suffix.
var quantity = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?(m|k|M|G|T|Ki|Mi|Gi|Ti)?$`)

// image is a container image reference: no spaces, no scheme.
var image = regexp.MustCompile(`^[a-z0-9][a-zA-Z0-9._/:@-]*[a-zA-Z0-9_.-]$`)

// labelKey and labelValue are what node_selector and tolerations take.
var (
	labelKey   = regexp.MustCompile(`^([a-z0-9]([-a-z0-9.]*[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$`)
	labelValue = regexp.MustCompile(`^([A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?)?$`)
)

// HasPod reports whether b names any of the pod keys.
func (b *Backend) HasPod() bool {
	return b.Image != "" || b.Resources != nil || len(b.NodeSelector) > 0 || len(b.Tolerations) > 0
}

// validatePod checks image, resources, node_selector and tolerations:
// for servers that speak stdio (a url server's connector runs in the
// gateway's pod), not privileged ones.
func (b *Backend) validatePod() error {
	if !b.HasPod() {
		return nil
	}
	switch {
	case b.URL != "":
		return errors.New("image, resources, node_selector, tolerations: only for a server with command (a url server's connector runs beside the gateway)")
	case b.Privileged:
		return errors.New("image, resources, node_selector, tolerations: not for a privileged server, which changes a host")
	}
	if b.Image == "" {
		return errors.New("resources, node_selector, tolerations: only with image")
	}
	if !image.MatchString(b.Image) || strings.Contains(b.Image, "://") {
		return fmt.Errorf("image: %q is not an image reference (registry/name:tag or @sha256:…)", b.Image)
	}
	if r := b.Resources; r != nil {
		for what, m := range map[string]map[string]string{"requests": r.Requests, "limits": r.Limits} {
			for _, k := range slices.Sorted(maps.Keys(m)) {
				if !slices.Contains(resourceNames, k) {
					return fmt.Errorf("resources.%s: %q is not one of %s", what, k, strings.Join(resourceNames, ", "))
				}
				if !quantity.MatchString(m[k]) {
					return fmt.Errorf("resources.%s.%s: %q is not a quantity (500m, 256Mi)", what, k, m[k])
				}
			}
		}
	}
	for _, k := range slices.Sorted(maps.Keys(b.NodeSelector)) {
		if !labelKey.MatchString(k) || !labelValue.MatchString(b.NodeSelector[k]) {
			return fmt.Errorf("node_selector: %q: %q is not a label", k, b.NodeSelector[k])
		}
	}
	for i, t := range b.Tolerations {
		key := fmt.Sprintf("tolerations[%d]", i)
		if t.Key != "" && !labelKey.MatchString(t.Key) {
			return fmt.Errorf("%s.key: %q is not a label key", key, t.Key)
		}
		switch t.Operator {
		case "", "Equal":
			if !labelValue.MatchString(t.Value) {
				return fmt.Errorf("%s.value: %q is not a label value", key, t.Value)
			}
		case "Exists":
			if t.Value != "" {
				return fmt.Errorf("%s.value: not with operator Exists", key)
			}
		default:
			return fmt.Errorf("%s.operator: %q (Equal or Exists)", key, t.Operator)
		}
		switch t.Effect {
		case "", "NoSchedule", "PreferNoSchedule", "NoExecute":
		default:
			return fmt.Errorf("%s.effect: %q (NoSchedule, PreferNoSchedule or NoExecute)", key, t.Effect)
		}
		if t.TolerationSeconds != nil && t.Effect != "NoExecute" {
			return fmt.Errorf("%s.toleration_seconds: only with effect NoExecute", key)
		}
	}
	return nil
}

// PodProblems returns what a pod cannot give b, each with the key and
// the reason: the parts of the systemd sandbox without an equivalent in
// a pod's security context (docs/architecture.md, section 5.12.3).
func (b *Backend) PodProblems() []string {
	const why = "not with the Kubernetes launcher: "
	var out []string
	refuse := func(key, reason string) { out = append(out, key+": "+why+reason) }
	if b.Image == "" {
		refuse("image", "an instance runs in a pod of its own, from the image the definition names")
	}
	if b.Privileged {
		refuse("privileged", "a privileged server changes a host; it stays behind a host gateway")
	}
	switch b.RunAs {
	case "", DefaultRunAs, HTTPRunAs:
	default:
		refuse("run_as", "an instance runs as a uid of its own, not as a named account")
	}
	if b.NetworkView != "" && b.NetworkView != NetworkViewNone {
		refuse("network_view", "a pod has no view of a host's network")
	}
	if b.Landlock != nil {
		refuse("landlock", "the pod's read-only root and its volumes take its place")
	}
	if len(b.Requires) > 0 {
		refuse("requires", "paths on a host have no meaning in a pod")
	}
	var sandbox []string
	s := b.Sandbox
	if s.ProtectHome != "" && s.ProtectHome != DefaultProtectHome {
		sandbox = append(sandbox, "protect_home")
	}
	if len(s.ReadWritePaths) > 0 {
		sandbox = append(sandbox, "read_write_paths")
	}
	if s.StateDirectory != "" {
		sandbox = append(sandbox, "state_directory")
	}
	if len(s.ReadDevices) > 0 {
		sandbox = append(sandbox, "read_devices")
	}
	if len(sandbox) > 0 {
		refuse("sandbox."+strings.Join(sandbox, ", sandbox."), "a pod has no host paths or devices to open")
	}
	if len(s.Capabilities) > 0 {
		// capabilities.add reaches only the bounding set of a container
		// that does not run as root: Kubernetes sets no ambient
		// capabilities, so the server would not have them.
		refuse("sandbox.capabilities", "a pod gives a uid other than root no ambient capabilities, so the server would not have them")
	}
	return out
}
