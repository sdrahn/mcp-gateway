package config

import (
	"strings"
	"testing"
)

const kubeYAML = `deployment: container
supervisor:
  mode: kubernetes
  kubernetes:
    namespace: mcp-instances
    bridge_image: registry.example.com/mcp-gateway:2.0.0
    gateway_namespace: mcp-gateway
    gateway_labels: {app.kubernetes.io/name: mcp-gateway}
`

func TestKubernetesLauncherConfig(t *testing.T) {
	g, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", kubeYAML+httpYAML))
	if err != nil {
		t.Fatal(err)
	}
	k := g.Supervisor.Kubernetes.WithDefaults()
	if !g.KubernetesLauncher() || k.ImagePullPolicy != "IfNotPresent" || k.StartTimeout != DefaultPodStartTimeout ||
		k.SELinux != "off" || k.APIServer != DefaultKubernetesAPIServer || k.TokenFile != DefaultKubernetesTokenFile || k.CAFile != DefaultKubernetesCAFile {
		t.Errorf("defaults %+v", k)
	}
	for content, want := range map[string]string{
		"supervisor:\n  mode: kubernetes\n" + httpYAML:                                                             "supervisor.mode: kubernetes only in container mode",
		"deployment: container\nsupervisor:\n  mode: kubernetes\n" + httpYAML:                                      "supervisor.kubernetes.namespace: required",
		strings.Replace(kubeYAML, "    gateway_labels: {app.kubernetes.io/name: mcp-gateway}\n", "", 1) + httpYAML: "gateway_labels: required",
		strings.Replace(kubeYAML, "namespace: mcp-instances", "namespace: MCP_Instances", 1) + httpYAML:            "is not a namespace name",
		kubeYAML + "    image_pull_policy: Sometimes\n" + httpYAML:                                                 "image_pull_policy",
		kubeYAML + "    selinux: auto\n" + httpYAML:                                                                "supervisor.kubernetes.selinux",
		kubeYAML + "    start_timeout: 1s\n" + httpYAML:                                                            "start_timeout: between 10s and 1h",
		kubeYAML + "    token_file: token\n" + httpYAML:                                                            "token_file: must be an absolute path",
	} {
		if _, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", content)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", content, err, want)
		}
	}

	// Stdio servers in pods of their own: what a pod cannot give is
	// refused; servers that speak HTTP as before.
	def := func(b Backend) *Backend {
		b.setDefaults()
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		return &b
	}
	podded := def(Backend{Name: "tickets", Command: []string{"/usr/bin/tickets"}, Image: "registry.example.com/tickets:1"})
	remote := def(Backend{Name: "remote", URL: "https://mcp.example.com/mcp"})
	if err := CheckDeployment(g, map[string]*Backend{"tickets": podded, "remote": remote}); err != nil {
		t.Errorf("kubernetes: %v", err)
	}
	noImage := def(Backend{Name: "fs", Command: []string{"/usr/bin/fs"}})
	typed := def(Backend{Name: "typed", Command: []string{"/usr/bin/t"}, Image: "registry.example.com/t:1", SELinuxType: "mcpsrv_t_t"})
	err = CheckDeployment(g, map[string]*Backend{"fs": noImage, "typed": typed})
	if err == nil || !strings.Contains(err.Error(), "server fs: image: not with the Kubernetes launcher") ||
		!strings.Contains(err.Error(), "server typed: selinux_type: not with the Kubernetes launcher unless") {
		t.Errorf("kubernetes refusals: %v", err)
	}
	g.Supervisor.Kubernetes.AllowSELinuxType = true
	if err := CheckDeployment(g, map[string]*Backend{"typed": typed}); err != nil {
		t.Errorf("selinux_type allowed: %v", err)
	}
	// With exec, stdio servers stay refused.
	g.Supervisor.Mode = "exec"
	if err := CheckDeployment(g, map[string]*Backend{"tickets": podded}); err == nil || !strings.Contains(err.Error(), "supervisor.mode: kubernetes and image") {
		t.Errorf("exec: %v", err)
	}
}
