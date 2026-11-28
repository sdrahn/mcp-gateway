package config

import (
	"strings"
	"testing"
)

// The shared store: container mode only, with the gateway's namespace;
// the API's settings default to supervisor.kubernetes's.
func TestReplication(t *testing.T) {
	const c = "deployment: container\n"
	g, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", c+httpYAML+"replication:\n  store: kubernetes\n  namespace: mcp-gateway\n"))
	if err != nil {
		t.Fatal(err)
	}
	r := g.Replication.WithDefaults()
	if !r.Shared() || r.Namespace != "mcp-gateway" || r.APIServer != DefaultKubernetesAPIServer ||
		r.TokenFile != DefaultKubernetesTokenFile || r.CAFile != DefaultKubernetesCAFile {
		t.Errorf("replication %+v", r)
	}
	h, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", "{}\n"))
	if err != nil || h.Replication.Shared() {
		t.Errorf("default: %v %+v", err, h.Replication)
	}
	for content, want := range map[string]string{
		"replication:\n  store: kubernetes\n  namespace: gw\n":               "replication.store: kubernetes only in container mode",
		c + httpYAML + "replication:\n  store: etcd\n":                       `replication.store: "etcd"`,
		c + httpYAML + "replication:\n  store: kubernetes\n":                 "replication.namespace: required",
		c + httpYAML + "replication:\n  store: kubernetes\n  namespace: A\n": `replication.namespace: "A" is not a namespace name`,
		c + httpYAML + "replication:\n  namespace: gw\n":                     "replication: set store: kubernetes, or nothing",
	} {
		if _, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", content)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", content, err, want)
		}
	}
}
