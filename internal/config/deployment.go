package config

import (
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
)

// Deployments (Gateway.Deployment; docs/architecture.md, section 5.12
// and decision D23).
const (
	// DeploymentHost runs on a host: instances as systemd units, confined
	// with SELinux, local clients on the Unix socket.
	DeploymentHost = "host"
	// DeploymentContainer runs in a container or a Kubernetes pod:
	// remote principals only, and servers that speak HTTP, whose
	// connectors run as child processes of the gateway.
	DeploymentContainer = "container"
)

// Container reports container mode.
func (g *Gateway) Container() bool { return g.Deployment == DeploymentContainer }

// RuntimeDir is the gateway's runtime directory: the socket's, or
// /run/mcp-gateway without one (container mode).
func (g *Gateway) RuntimeDir() string {
	if g.Socket == "" {
		return filepath.Dir(DefaultSocket)
	}
	return filepath.Dir(g.Socket)
}

// validateDeployment checks the deployment and, in container mode, the
// keys that have no meaning there: what a host gives (systemd, the Unix
// socket and local principals, the kernel audit) is refused with the
// reason, not ignored.
func (g *Gateway) validateDeployment() error {
	switch g.Deployment {
	case DeploymentHost:
		return nil
	case DeploymentContainer:
	default:
		return fmt.Errorf("deployment: unknown value %q (host or container)", g.Deployment)
	}
	var errs []error
	refuse := func(key, why string) {
		errs = append(errs, fmt.Errorf("%s: not in container mode (deployment: container): %s", key, why))
	}
	if g.Socket != "" {
		refuse("socket", "there are no local clients; agents connect to the HTTP listener")
	}
	if g.SocketGroup != "" {
		refuse("socket_group", "there is no Unix socket for local clients")
	}
	if g.Supervisor.Mode != "exec" {
		refuse("supervisor.mode", "instances run as child processes of the gateway (exec); there is no systemd to start units")
	}
	if g.Audit.Kernel == "on" {
		refuse("audit.kernel", "a container has no kernel audit of its own; the audit records go to the standard error, which the container runtime collects")
	}
	if g.HTTP.Listen == "" {
		errs = append(errs, errors.New("http.listen: container mode (deployment: container) needs the HTTP listener: every principal is remote"))
	}
	if g.HTTP.LocalUserClaim != "" {
		refuse("http.local_user_claim", "there are no local accounts to map principals to")
	}
	for i, is := range g.HTTP.Issuers {
		if is.LocalUserClaim != "" {
			refuse(fmt.Sprintf("http.issuers[%d].local_user_claim", i), "there are no local accounts to map principals to")
		}
	}
	return errors.Join(errs...)
}

// CheckDeployment checks the server definitions against the deployment:
// in container mode, only servers that speak HTTP, without the keys of a
// host's sandbox. It names every key it refuses.
func CheckDeployment(g *Gateway, backends map[string]*Backend) error {
	if !g.Container() {
		return nil
	}
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(backends)) {
		for _, p := range backends[name].ContainerProblems() {
			errs = append(errs, fmt.Errorf("server %s: %s", name, p))
		}
	}
	return errors.Join(errs...)
}

// ContainerProblems returns what container mode refuses in b, each with
// the key and the reason; none for a server that speaks HTTP with the
// defaults of one.
func (b *Backend) ContainerProblems() []string {
	const mode = "not in container mode (deployment: container): "
	if b.URL == "" {
		// Privileged servers too: they have a command.
		return []string{"command: " + mode + "a server that speaks stdio would run as a child process in the gateway's container, with its account and secrets, which isolates nothing; run it as a server that speaks HTTP, or wait for the Kubernetes launcher (pods of their own, roadmap step 47)"}
	}
	var out []string
	refuse := func(key, why string) { out = append(out, key+": "+mode+why) }
	if b.RunAs != HTTPRunAs {
		refuse("run_as", "the connector runs as the gateway's account")
	}
	if b.SELinuxType != HTTPSELinuxType {
		refuse("selinux_type", "there are no SELinux domains for instances in a container")
	}
	if b.NetworkView != NetworkViewNone {
		refuse("network_view", "there is no host network to show")
	}
	if b.Landlock != nil {
		refuse("landlock", "the connector runs without a Landlock launcher in a container")
	}
	if len(b.Requires) > 0 {
		refuse("requires", "paths on a host have no meaning in a container")
	}
	var sandbox []string
	s := b.Sandbox
	if s.ProtectHome != DefaultProtectHome {
		sandbox = append(sandbox, "protect_home")
	}
	if len(s.ReadWritePaths) > 0 {
		sandbox = append(sandbox, "read_write_paths")
	}
	if s.StateDirectory != "" {
		sandbox = append(sandbox, "state_directory")
	}
	if len(s.Capabilities) > 0 {
		sandbox = append(sandbox, "capabilities")
	}
	if len(s.ReadDevices) > 0 {
		sandbox = append(sandbox, "read_devices")
	}
	if len(sandbox) > 0 {
		refuse("sandbox."+strings.Join(sandbox, ", sandbox."), "there is no systemd sandbox in a container")
	}
	return out
}
