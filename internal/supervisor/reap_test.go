package supervisor

import (
	"context"
	"slices"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/kube"
	"github.com/sdrahn/mcp-gateway/internal/kube/kubetest"
)

// Reap deletes the pods of replicas that are gone and of no replica, and
// keeps the live replicas' and what the gateway did not make.
func TestReap(t *testing.T) {
	api := kubetest.NewSecrets(t)
	pod := func(name string, labels map[string]string) {
		api.PutObject("pods", "inst", kube.Pod{APIVersion: "v1", Kind: "Pod", Metadata: kube.ObjectMeta{Name: name, Labels: labels}})
	}
	ours := func(replica string) map[string]string {
		l := map[string]string{LabelManagedBy: managedBy, LabelServer: "fs"}
		if replica != "" {
			l[LabelReplica] = replica
		}
		return l
	}
	pod("a-1", ours("gw-a"))
	pod("b-1", ours("gw-b"))
	pod("b-2", ours("gw-b"))
	pod("old-1", ours(""))
	pod("other", map[string]string{"app": "other"})
	k := &Kubernetes{Client: api.Client(), Options: PodOptions{Namespace: "inst"}}
	gone, err := k.Reap(context.Background(), func(r string) bool { return r == "gw-a" })
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(gone, []string{"", "gw-b"}) {
		t.Errorf("reaped %v", gone)
	}
	left := api.Names("pods", "inst", "")
	slices.Sort(left)
	if !slices.Equal(left, []string{"a-1", "other"}) {
		t.Errorf("pods left %v", left)
	}
	if gone, _ := k.Reap(context.Background(), func(string) bool { return true }); len(gone) != 0 {
		t.Errorf("reaped again %v", gone)
	}
}

// With several replicas, an instance's pod names its replica; with one
// gateway it does not.
func TestInstancePodReplica(t *testing.T) {
	b := podBackend(t, config.Backend{Name: "fs", Command: []string{"/usr/bin/fs"}, Image: "registry.example.com/fs:1"})
	o := podOpts
	objs, err := InstancePod(b, remotePrincipal(), "abc", o, nil, "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := objs.Pod.Metadata.Labels[LabelReplica]; ok {
		t.Errorf("one gateway: labels %v", objs.Pod.Metadata.Labels)
	}
	o.Replica = "mcp-gateway-6d4f-x2"
	if objs, err = InstancePod(b, remotePrincipal(), "abc", o, nil, "x"); err != nil {
		t.Fatal(err)
	}
	if objs.Pod.Metadata.Labels[LabelReplica] != "mcp-gateway-6d4f-x2" {
		t.Errorf("a replica's pod: labels %v", objs.Pod.Metadata.Labels)
	}
}
