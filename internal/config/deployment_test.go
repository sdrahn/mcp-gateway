package config

import (
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/landlock"
)

// Container mode: no Unix socket, child processes, no kernel audit; the
// keys of a host are refused with the reason.
func TestDeploymentContainer(t *testing.T) {
	g, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", "deployment: container\n"+httpYAML))
	if err != nil {
		t.Fatal(err)
	}
	if !g.Container() || g.Socket != "" || g.Supervisor.Mode != "exec" || g.Audit.Kernel != "off" ||
		g.RuntimeDir() != "/run/mcp-gateway" {
		t.Errorf("container defaults: deployment %q socket %q mode %q kernel %q runtime %q",
			g.Deployment, g.Socket, g.Supervisor.Mode, g.Audit.Kernel, g.RuntimeDir())
	}
	h, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", "{}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if h.Deployment != DeploymentHost || h.Container() || h.RuntimeDir() != "/run/mcp-gateway" {
		t.Errorf("host defaults: %q %q", h.Deployment, h.RuntimeDir())
	}

	const c = "deployment: container\n"
	for content, want := range map[string]string{
		c + "socket: /run/x.sock\n" + httpYAML:          "socket: not in container mode",
		c + "socket_group: mcp\n" + httpYAML:            "socket_group: not in container mode",
		c + "supervisor:\n  mode: systemd\n" + httpYAML: "supervisor.mode: not in container mode",
		c + "audit:\n  kernel: \"on\"\n" + httpYAML:     "audit.kernel: not in container mode",
		c + httpYAML + "  local_user_claim: uid\n":      "http.local_user_claim: not in container mode",
	} {
		if _, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", content)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", content, err, want)
		}
	}
	if _, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", "deployment: container\n")); err == nil ||
		!strings.Contains(err.Error(), "http.listen: container mode") {
		t.Errorf("without http.listen: %v", err)
	}
	if _, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", "deployment: cloud\n")); err == nil ||
		!strings.Contains(err.Error(), `deployment: unknown value "cloud"`) {
		t.Errorf("unknown deployment: %v", err)
	}
	// Every refusal at once, each named.
	_, err = LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", "deployment: container\nsocket: /run/x.sock\nsupervisor:\n  mode: systemd\n"))
	for _, want := range []string{"socket:", "supervisor.mode:", "http.listen:"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("all refusals: %v, want %q", err, want)
		}
	}
}

func TestCheckDeployment(t *testing.T) {
	def := func(b Backend) *Backend {
		b.setDefaults()
		if err := b.Validate(); err != nil {
			t.Fatalf("%+v: %v", b, err)
		}
		return &b
	}
	remote := def(Backend{Name: "remote", URL: "https://mcp.example.com/mcp"})
	stdio := def(Backend{Name: "fs", Command: []string{"/usr/bin/mcp-server-fs"}})
	host := &Gateway{Deployment: DeploymentHost}
	container := &Gateway{Deployment: DeploymentContainer}
	if err := CheckDeployment(host, map[string]*Backend{"fs": stdio, "remote": remote}); err != nil {
		t.Errorf("host: %v", err)
	}
	if err := CheckDeployment(container, map[string]*Backend{"remote": remote}); err != nil {
		t.Errorf("container, remote: %v", err)
	}
	err := CheckDeployment(container, map[string]*Backend{"fs": stdio, "remote": remote})
	if err == nil || !strings.Contains(err.Error(), "server fs: command: not in container mode") ||
		!strings.Contains(err.Error(), "step 47") || strings.Contains(err.Error(), "server remote") {
		t.Errorf("container, stdio: %v", err)
	}

	for _, c := range []struct {
		b    Backend
		want []string
	}{
		{Backend{URL: "https://x/", RunAs: "principal"}, []string{"run_as:"}},
		{Backend{URL: "https://x/", SELinuxType: "mcp_backend_t"}, []string{"selinux_type:"}},
		{Backend{URL: "https://x/", Requires: []string{"/run/x"}}, []string{"requires:"}},
		{Backend{URL: "https://x/", Landlock: &landlock.Rules{Read: []string{"/usr"}}}, []string{"landlock:"}},
		{Backend{URL: "https://x/", Sandbox: Sandbox{ProtectHome: "yes", StateDirectory: "x"}},
			[]string{"sandbox.protect_home, sandbox.state_directory:"}},
		{Backend{URL: "https://x/", RunAs: "principal", SELinuxType: "mcp_backend_t"}, []string{"run_as:", "selinux_type:"}},
	} {
		c.b.Name = "x"
		c.b.setDefaults()
		got := strings.Join(c.b.ContainerProblems(), "\n")
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%+v: %q, want %q", c.b, got, w)
			}
		}
		if n := len(c.b.ContainerProblems()); n != len(c.want) {
			t.Errorf("%+v: %d problems, want %d: %q", c.b, n, len(c.want), got)
		}
	}
}
