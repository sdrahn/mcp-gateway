package supervisor

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/kube"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

var podOpts = PodOptions{Namespace: "mcp-instances", BridgeImage: "registry.example.com/mcp-gateway:2.0.0",
	GatewayNamespace: "mcp-gateway", GatewayLabels: map[string]string{"app.kubernetes.io/name": "mcp-gateway"}}

func remotePrincipal() principal.Principal {
	return principal.Principal{Sub: "k8s:system:serviceaccount:agents:custos", Issuer: "https://kubernetes.default.svc.cluster.local",
		Transport: principal.TransportHTTP}
}

func podBackend(t *testing.T, b config.Backend) *config.Backend {
	t.Helper()
	b.ApplyDefaults()
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	return &b
}

// The pod of a definition gives it what the systemd sandbox of the same
// definition gives it, property by property (docs/architecture.md,
// section 5.12.3).
func TestInstancePodTranslatesSandbox(t *testing.T) {
	for _, network := range []bool{false, true} {
		t.Run(fmt.Sprintf("network=%v", network), func(t *testing.T) {
			b := podBackend(t, config.Backend{Name: "tickets", Command: []string{"/usr/bin/tickets-mcp", "--stdio"},
				Image: "registry.example.com/tickets-mcp:1.2", Network: network,
				Env: map[string]string{"TICKETS_URL": "https://tickets.example.com"}})
			p := remotePrincipal()
			props := propMap(t, &Systemd{}, b, p, "c12,c34")
			o := podOpts
			o.MCSLevel = "s0:c12,c34"
			objs, err := InstancePod(b, p, "0123456789abcdef", o, nil, "bridge-secret")
			if err != nil {
				t.Fatal(err)
			}
			pod := objs.Pod
			c := pod.Spec.Containers[0]
			psc, sc := pod.Spec.SecurityContext, c.SecurityContext

			// NoNewPrivileges= → allowPrivilegeEscalation: false
			if props["NoNewPrivileges"] != true || *sc.AllowPrivilegeEscalation || *sc.Privileged {
				t.Errorf("NoNewPrivileges %v, allowPrivilegeEscalation %v", props["NoNewPrivileges"], *sc.AllowPrivilegeEscalation)
			}
			// ProtectSystem=strict → readOnlyRootFilesystem
			if props["ProtectSystem"] != "strict" || !*sc.ReadOnlyRootFilesystem {
				t.Errorf("ProtectSystem %v, readOnlyRootFilesystem %v", props["ProtectSystem"], *sc.ReadOnlyRootFilesystem)
			}
			// PrivateTmp= → an emptyDir at /tmp
			if props["PrivateTmp"] != true || !slices.ContainsFunc(c.VolumeMounts, func(m kube.VolumeMount) bool { return m.MountPath == "/tmp" && !m.ReadOnly }) {
				t.Errorf("PrivateTmp %v, mounts %+v", props["PrivateTmp"], c.VolumeMounts)
			}
			// CapabilityBoundingSet= (none) → drop ALL, add nothing
			if props["CapabilityBoundingSet"] != uint64(0) || !slices.Equal(sc.Capabilities.Drop, []string{"ALL"}) || len(sc.Capabilities.Add) > 0 {
				t.Errorf("CapabilityBoundingSet %v, capabilities %+v", props["CapabilityBoundingSet"], sc.Capabilities)
			}
			// SystemCallFilter=@system-service → RuntimeDefault
			if props["SystemCallFilter"] == nil || psc.SeccompProfile.Type != "RuntimeDefault" {
				t.Errorf("seccomp %+v", psc.SeccompProfile)
			}
			// MemoryMax= → limits.memory
			if props["MemoryMax"] != uint64(instanceMemoryMax) || c.Resources.Limits["memory"] != "512Mi" {
				t.Errorf("MemoryMax %v, limits %v", props["MemoryMax"], c.Resources.Limits)
			}
			// RuntimeMaxSec= → activeDeadlineSeconds
			if props["RuntimeMaxUSec"] != uint64(instanceRuntimeMax/time.Microsecond) || *pod.Spec.ActiveDeadlineSeconds != int64(instanceRuntimeMax/time.Second) {
				t.Errorf("RuntimeMaxUSec %v, activeDeadlineSeconds %d", props["RuntimeMaxUSec"], *pod.Spec.ActiveDeadlineSeconds)
			}
			// DynamicUser= → a high uid of its own, never root
			if props["DynamicUser"] != true || *psc.RunAsUser < instanceUIDBase || !*psc.RunAsNonRoot || *psc.RunAsGroup != *psc.RunAsUser {
				t.Errorf("DynamicUser %v, runAsUser %d", props["DynamicUser"], *psc.RunAsUser)
			}
			// SELinuxContext=…:s0:c12,c34 → seLinuxOptions.level, no type
			if !strings.HasSuffix(props["SELinuxContext"].(string), ":s0:c12,c34") || psc.SELinuxOptions.Level != "s0:c12,c34" || psc.SELinuxOptions.Type != "" {
				t.Errorf("SELinuxContext %v, seLinuxOptions %+v", props["SELinuxContext"], psc.SELinuxOptions)
			}
			// Environment= → env, the same variables
			var env []string
			for _, e := range c.Env {
				env = append(env, e.Name+"="+e.Value)
			}
			if !slices.Equal(env, props["Environment"].([]string)) {
				t.Errorf("env %q, Environment %q", env, props["Environment"])
			}
			// ExecStart= → the bridge, then the same command line
			dash := slices.Index(c.Args, "--")
			if c.Command[0] != bridgeDir+"/mcp-stdio-bridge" || dash < 0 || !slices.Equal(c.Args[dash+1:], command(b, p)) ||
				!strings.Contains(fmt.Sprint(props["ExecStart"]), "/usr/bin/tickets-mcp") {
				t.Errorf("command %q %q", c.Command, c.Args)
			}
			// PrivateNetwork= / RestrictAddressFamilies=AF_UNIX → no
			// egress; network: true → any.
			egress := objs.Policy.Spec.Egress
			if props["PrivateNetwork"] == network || (network && len(egress) != 1) || (!network && len(egress) != 0) {
				t.Errorf("PrivateNetwork %v, egress %+v", props["PrivateNetwork"], egress)
			}
			if _, restricted := props["RestrictAddressFamilies"]; restricted == network {
				t.Errorf("RestrictAddressFamilies with network %v", network)
			}

			// Beyond the unit: no token, no service links, no host
			// namespaces; the bridge from the gateway's image; only the
			// gateway reaches it.
			if *pod.Spec.AutomountServiceAccountToken || *pod.Spec.EnableServiceLinks || pod.Spec.HostNetwork || pod.Spec.HostPID ||
				pod.Spec.RestartPolicy != "Never" {
				t.Errorf("pod spec %+v", pod.Spec)
			}
			if ic := pod.Spec.InitContainers[0]; ic.Image != podOpts.BridgeImage || ic.Command[1] != bridgeBinary || !*ic.SecurityContext.ReadOnlyRootFilesystem {
				t.Errorf("init container %+v", ic)
			}
			in := objs.Policy.Spec.Ingress
			if len(in) != 1 || in[0].Ports[0].Port != BridgePort || in[0].From[0].PodSelector.MatchLabels["app.kubernetes.io/name"] != "mcp-gateway" ||
				in[0].From[0].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != "mcp-gateway" ||
				!slices.Equal(objs.Policy.Spec.PolicyTypes, []string{"Ingress", "Egress"}) ||
				objs.Policy.Spec.PodSelector.MatchLabels[LabelInstance] != "0123456789abcdef" {
				t.Errorf("policy %+v", objs.Policy.Spec)
			}
			if objs.Secret.StringData[bridgeTokenKey] != "bridge-secret" || !objs.Secret.Immutable || len(objs.Secret.StringData) != 1 {
				t.Errorf("secret %+v", objs.Secret)
			}
			if pod.Metadata.Name != "mcp-tickets-0123456789abcdef" || pod.Metadata.Namespace != "mcp-instances" ||
				pod.Metadata.Labels[LabelServer] != "tickets" || pod.Metadata.Labels[LabelManagedBy] != "mcp-gateway" {
				t.Errorf("metadata %+v", pod.Metadata)
			}
		})
	}
}

// LoadCredential= → the instance's Secret, at $CREDENTIALS_DIRECTORY;
// resources, node_selector and tolerations from the definition.
func TestInstancePodCredentialsAndPlacement(t *testing.T) {
	sec := int64(30)
	b := podBackend(t, config.Backend{Name: "tickets", Command: []string{"/usr/bin/tickets-mcp"},
		Image: "registry.example.com/tickets-mcp:1.2", Credentials: []string{"api-token", "db:/srv/db.pass"},
		Resources:    &config.Resources{Requests: map[string]string{"cpu": "100m"}, Limits: map[string]string{"memory": "1Gi", "cpu": "1"}},
		NodeSelector: map[string]string{"kubernetes.io/arch": "amd64"},
		Tolerations:  []config.Toleration{{Key: "dedicated", Operator: "Equal", Value: "mcp", Effect: "NoExecute", TolerationSeconds: &sec}}})
	props := propMap(t, &Systemd{}, b, remotePrincipal(), "")
	if _, ok := props["LoadCredential"]; !ok {
		t.Fatal("no LoadCredential for the unit")
	}
	if _, err := InstancePod(b, remotePrincipal(), "abc", podOpts, map[string]string{"api-token": "t"}, "x"); err == nil ||
		!strings.Contains(err.Error(), "credential db was not read") {
		t.Errorf("a credential not read: %v", err)
	}
	objs, err := InstancePod(b, remotePrincipal(), "abc", podOpts, map[string]string{"api-token": "t", "db": "pw"}, "x")
	if err != nil {
		t.Fatal(err)
	}
	if objs.Secret.StringData["credential.api-token"] != "t" || objs.Secret.StringData["credential.db"] != "pw" {
		t.Errorf("secret %v", objs.Secret.StringData)
	}
	c := objs.Pod.Spec.Containers[0]
	if !slices.Contains(c.Env, kube.EnvVar{Name: "CREDENTIALS_DIRECTORY", Value: credentialsDir}) ||
		!slices.ContainsFunc(c.VolumeMounts, func(m kube.VolumeMount) bool { return m.MountPath == credentialsDir && m.ReadOnly }) {
		t.Errorf("container %+v", c)
	}
	for _, v := range objs.Pod.Spec.Volumes {
		if v.Name == "credentials" && (len(v.Secret.Items) != 2 || v.Secret.Items[1] != (kube.KeyToPath{Key: "credential.db", Path: "db"})) {
			t.Errorf("credentials volume %+v", v.Secret)
		}
	}
	if c.Resources.Limits["memory"] != "1Gi" || c.Resources.Limits["cpu"] != "1" || c.Resources.Requests["cpu"] != "100m" {
		t.Errorf("resources %+v", c.Resources)
	}
	if objs.Pod.Spec.NodeSelector["kubernetes.io/arch"] != "amd64" || len(objs.Pod.Spec.Tolerations) != 1 ||
		*objs.Pod.Spec.Tolerations[0].TolerationSeconds != 30 {
		t.Errorf("placement %+v %+v", objs.Pod.Spec.NodeSelector, objs.Pod.Spec.Tolerations)
	}
}

// What a pod cannot give is refused, with the key and the reason.
func TestInstancePodRefuses(t *testing.T) {
	base := config.Backend{Name: "x", Command: []string{"/usr/bin/x"}, Image: "registry.example.com/x:1"}
	for _, c := range []struct {
		edit func(*config.Backend)
		want string
	}{
		{func(b *config.Backend) { b.Image = "" }, "image: not with the Kubernetes launcher"},
		{func(b *config.Backend) { b.RunAs = "nobody" }, "run_as:"},
		{func(b *config.Backend) { b.Sandbox.Capabilities = []string{"CAP_NET_ADMIN"} }, "sandbox.capabilities: not with the Kubernetes launcher: a pod gives"},
		{func(b *config.Backend) { b.Sandbox.ReadWritePaths = []string{"/srv"} }, "sandbox.read_write_paths:"},
		{func(b *config.Backend) { b.Requires = []string{"/run/x"} }, "requires:"},
		{func(b *config.Backend) { b.NetworkView = config.NetworkViewHost }, "network_view:"},
	} {
		b := base
		c.edit(&b)
		b.ApplyDefaults()
		if _, err := InstancePod(&b, remotePrincipal(), "abc", podOpts, nil, "x"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", b, err, c.want)
		}
	}
	b := base
	b.ApplyDefaults()
	if _, err := InstancePod(&b, remotePrincipal(), "abc", PodOptions{}, nil, "x"); err == nil {
		t.Error("no namespace or bridge image accepted")
	}
	if _, err := InstancePod(&b, remotePrincipal(), "abc", podOpts, nil, ""); err == nil {
		t.Error("no bridge token accepted")
	}
}

// The API's field names, and the fields that must be there even when
// false (an omitted automountServiceAccountToken mounts the token).
func TestInstancePodJSON(t *testing.T) {
	b := podBackend(t, config.Backend{Name: "x", Command: []string{"/usr/bin/x"}, Image: "registry.example.com/x:1"})
	objs, err := InstancePod(b, remotePrincipal(), "abc", podOpts, nil, "x")
	if err != nil {
		t.Fatal(err)
	}
	pod, _ := json.Marshal(objs.Pod)
	for _, want := range []string{`"apiVersion":"v1"`, `"kind":"Pod"`, `"automountServiceAccountToken":false`, `"enableServiceLinks":false`,
		`"allowPrivilegeEscalation":false`, `"readOnlyRootFilesystem":true`, `"restartPolicy":"Never"`, `"seccompProfile":{"type":"RuntimeDefault"}`} {
		if !strings.Contains(string(pod), want) {
			t.Errorf("pod JSON lacks %s: %s", want, pod)
		}
	}
	np, _ := json.Marshal(objs.Policy)
	if !strings.Contains(string(np), `"egress":[]`) || !strings.Contains(string(np), `"apiVersion":"networking.k8s.io/v1"`) {
		t.Errorf("policy JSON: %s", np)
	}
	if InstanceUID("abc") == InstanceUID("abd") || InstanceUID("abc") < instanceUIDBase || InstanceUID("abc") >= instanceUIDBase+instanceUIDs {
		t.Errorf("uids %d %d", InstanceUID("abc"), InstanceUID("abd"))
	}
	if n := InstanceName("a-server-with-a-rather-long-name", strings.Repeat("f", 40)); len(n) > 63 {
		t.Errorf("name %q", n)
	}
}
