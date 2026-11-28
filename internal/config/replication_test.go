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
		"replication:\n  store: kubernetes\n  namespace: gw\n":                                     "replication.store: kubernetes only in container mode",
		c + httpYAML + "replication:\n  store: etcd\n":                                             `replication.store: "etcd"`,
		c + httpYAML + "replication:\n  store: kubernetes\n":                                       "replication.namespace: required",
		c + httpYAML + "replication:\n  store: kubernetes\n  namespace: A\n":                       `replication.namespace: "A" is not a namespace name`,
		c + httpYAML + "replication:\n  namespace: gw\n":                                           "replication: set store: kubernetes, or nothing",
		c + httpYAML + "replication:\n  store: kubernetes\n  namespace: gw\n  replica: GW_1\n":     `replication.replica: "GW_1" is not a label value`,
		c + httpYAML + "replication:\n  store: kubernetes\n  namespace: gw\n  listen: \":8444\"\n": "replication.peer_cert_file: required with replication.listen",
		c + httpYAML + "replication:\n  store: kubernetes\n  namespace: gw\n  listen: \"8444\"\n":  `replication.listen: "8444" is not host:port`,
		c + httpYAML + "replication:\n  store: kubernetes\n  namespace: gw\n  peer_ca_file: /ca\n": "replication.peer_*: only with replication.listen",
	} {
		if _, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", content)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", content, err, want)
		}
	}
}

// The replica's name: set, or from the pod's ($POD_NAME); a label value.
func TestCheckReplica(t *testing.T) {
	if err := CheckReplica("mcp-gateway-6d4f9c7b8-x2kqp"); err != nil {
		t.Error(err)
	}
	if err := CheckReplica(""); err == nil || !strings.Contains(err.Error(), "$POD_NAME is empty") {
		t.Errorf("unset: %v", err)
	}
}

// Forwarding: with the peer listener and the replicas' certificate.
func TestReplicationForwarding(t *testing.T) {
	g, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", "deployment: container\n"+httpYAML+
		"replication:\n  store: kubernetes\n  namespace: gw\n  listen: \":8444\"\n  peer_cert_file: /c\n  peer_key_file: /k\n  peer_ca_file: /ca\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !g.Replication.Forwarding() || g.Replication.WithDefaults().PeerServerName != DefaultPeerServerName {
		t.Errorf("forwarding %+v", g.Replication)
	}
}
