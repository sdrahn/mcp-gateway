package config

import (
	"strings"
	"testing"
)

func TestBackendPodKeys(t *testing.T) {
	sec := int64(60)
	ok := Backend{Name: "x", Command: []string{"/usr/bin/x"}, Image: "registry.example.com/team/x-mcp:1.2@sha256:abcd",
		Resources:    &Resources{Requests: map[string]string{"cpu": "250m", "memory": "64Mi"}, Limits: map[string]string{"memory": "1Gi", "ephemeral-storage": "1G"}},
		NodeSelector: map[string]string{"kubernetes.io/arch": "amd64", "node-role": "mcp"},
		Tolerations: []Toleration{{Key: "dedicated", Operator: "Equal", Value: "mcp", Effect: "NoSchedule"},
			{Operator: "Exists", Effect: "NoExecute", TolerationSeconds: &sec}}}
	ok.setDefaults()
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if !ok.HasPod() {
		t.Error("HasPod false")
	}
	for _, c := range []struct {
		edit func(*Backend)
		want string
	}{
		{func(b *Backend) { b.Image = "https://registry.example.com/x" }, "image: "},
		{func(b *Backend) { b.Image = "x y" }, "image: "},
		{func(b *Backend) { b.Image = "" }, "only with image"},
		{func(b *Backend) { b.Resources.Limits["gpu"] = "1" }, `resources.limits: "gpu"`},
		{func(b *Backend) { b.Resources.Requests["cpu"] = "lots" }, "resources.requests.cpu"},
		{func(b *Backend) { b.NodeSelector["a b"] = "c" }, "node_selector"},
		{func(b *Backend) { b.Tolerations[0].Operator = "In" }, "tolerations[0].operator"},
		{func(b *Backend) { b.Tolerations[1].Value = "v" }, "tolerations[1].value: not with operator Exists"},
		{func(b *Backend) { b.Tolerations[0].Effect = "Never" }, "tolerations[0].effect"},
		{func(b *Backend) { b.Tolerations[0].TolerationSeconds = &sec }, "toleration_seconds: only with effect NoExecute"},
		{func(b *Backend) { b.Command = nil; b.URL = "https://x.example.com/mcp" }, "only for a server with command"},
	} {
		b := ok
		b.Resources = &Resources{Requests: map[string]string{"cpu": "250m"}, Limits: map[string]string{"memory": "1Gi"}}
		b.NodeSelector = map[string]string{"kubernetes.io/arch": "amd64"}
		b.Tolerations = append([]Toleration(nil), ok.Tolerations...)
		b.Command = []string{"/usr/bin/x"}
		c.edit(&b)
		b.setDefaults()
		if err := b.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v, want %q", err, c.want)
		}
	}
	// On a host an instance is a unit: the keys are refused there.
	err := CheckDeployment(&Gateway{Deployment: DeploymentHost}, map[string]*Backend{"x": &ok})
	if err == nil || !strings.Contains(err.Error(), "server x: image, resources, node_selector, tolerations: only with the Kubernetes launcher") {
		t.Errorf("host: %v", err)
	}
	if p := ok.PodProblems(); len(p) != 0 {
		t.Errorf("pod problems of a plain definition: %q", p)
	}
}
