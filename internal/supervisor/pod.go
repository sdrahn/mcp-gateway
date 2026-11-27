package supervisor

import (
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/kube"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// The Kubernetes launcher's pods (docs/architecture.md, section 5.12.3):
// an instance is a pod of its own, from the definition's image, its
// stdio carried to the gateway by mcp-stdio-bridge, which an init
// container copies in from the gateway's image. The systemd sandbox of
// sandboxProperties is translated property by property; what has no
// equivalent in a pod is refused (config.Backend.PodProblems).

const (
	// BridgePort is where an instance's mcp-stdio-bridge listens.
	BridgePort = 8765
	// bridgeBinary is the bridge in the gateway's image, and bridgeDir
	// where the init container puts it in the instance's pod.
	bridgeBinary = "/usr/libexec/mcp-gateway/mcp-stdio-bridge"
	bridgeDir    = "/mcp-bridge"
	// bridgeSecretDir holds the bridge's token; credentialsDir the
	// definition's credentials ($CREDENTIALS_DIRECTORY).
	bridgeSecretDir = "/run/mcp-bridge"
	credentialsDir  = "/run/credentials"
	// Secret keys: the bridge's token, and each credential's prefix.
	bridgeTokenKey      = "bridge-token"
	credentialKeyPrefix = "credential."
	// Labels of an instance's objects.
	LabelManagedBy = "app.kubernetes.io/managed-by"
	LabelServer    = "mcp-gateway.sdrahn.github.io/server"
	LabelInstance  = "mcp-gateway.sdrahn.github.io/instance"
	managedBy      = "mcp-gateway"
	// Instances run as a uid of their own, in [instanceUIDBase,
	// instanceUIDBase+instanceUIDs): never root, never a system account.
	instanceUIDBase = 100000
	instanceUIDs    = 900000
)

// PodOptions configure the Kubernetes launcher's pods.
type PodOptions struct {
	// Namespace is where instances run: one of their own.
	Namespace string
	// BridgeImage is the gateway's image, which carries mcp-stdio-bridge.
	BridgeImage     string
	ImagePullPolicy string
	// GatewayNamespace and GatewayLabels select the gateway's pods, the
	// only ones that may reach an instance's bridge.
	GatewayNamespace string
	GatewayLabels    map[string]string
	// MCSLevel ("s0:c12,c34") separates two instances of one image on
	// nodes that run SELinux; empty: none.
	MCSLevel string
	// AllowSELinuxType passes a definition's selinux_type to the pod
	// (the nodes' policy must have it).
	AllowSELinuxType bool
}

// InstanceObjects are what an instance is in a cluster.
type InstanceObjects struct {
	Pod    kube.Pod
	Policy kube.NetworkPolicy
	Secret kube.Secret
}

// InstancePod returns the pod, NetworkPolicy and Secret of an instance
// of b for p: id names it, credentials are the contents of the
// definition's credentials by name (read by the gateway: no systemd
// reads them for it in a cluster), bridgeToken the secret the bridge
// asks the gateway for.
func InstancePod(b *config.Backend, p principal.Principal, id string, o PodOptions, credentials map[string]string, bridgeToken string) (*InstanceObjects, error) {
	if problems := b.PodProblems(); len(problems) > 0 {
		return nil, fmt.Errorf("server %s: %s", b.Name, strings.Join(problems, "; "))
	}
	if b.URL != "" {
		return nil, fmt.Errorf("server %s: a url server's connector runs beside the gateway, not in a pod", b.Name)
	}
	if err := CheckUser(b, p); err != nil {
		return nil, err
	}
	if o.Namespace == "" || o.BridgeImage == "" || bridgeToken == "" {
		return nil, errors.New("kubernetes launcher: namespace, the bridge's image and its token are required")
	}
	name := InstanceName(b.Name, id)
	labels := map[string]string{LabelManagedBy: managedBy, LabelServer: b.Name, LabelInstance: id}
	meta := kube.ObjectMeta{Name: name, Namespace: o.Namespace, Labels: labels}

	creds, err := b.ParseCredentials()
	if err != nil {
		return nil, err
	}
	secret := kube.Secret{APIVersion: "v1", Kind: "Secret", Metadata: meta, Type: "Opaque", Immutable: true,
		StringData: map[string]string{bridgeTokenKey: bridgeToken}}
	var credItems []kube.KeyToPath
	for _, c := range creds {
		v, ok := credentials[c.Name]
		if !ok {
			return nil, fmt.Errorf("server %s: credential %s was not read", b.Name, c.Name)
		}
		secret.StringData[credentialKeyPrefix+c.Name] = v
		credItems = append(credItems, kube.KeyToPath{Key: credentialKeyPrefix + c.Name, Path: c.Name})
	}

	uid := InstanceUID(id)
	env := []kube.EnvVar{}
	for _, kv := range environment(b, p) {
		k, v, _ := strings.Cut(kv, "=")
		env = append(env, kube.EnvVar{Name: k, Value: v})
	}
	if len(creds) > 0 {
		env = append(env, kube.EnvVar{Name: "CREDENTIALS_DIRECTORY", Value: credentialsDir})
	}
	argv := command(b, p)
	args := append([]string{"-listen", ":" + strconv.Itoa(BridgePort), "-token-file", bridgeSecretDir + "/token", "--"}, argv...)

	resources := &kube.ResourceRequirements{Limits: map[string]string{
		// MemoryMax=
		"memory": strconv.Itoa(instanceMemoryMax>>20) + "Mi",
	}}
	if r := b.Resources; r != nil {
		if len(r.Requests) > 0 {
			resources.Requests = maps.Clone(r.Requests)
		}
		maps.Copy(resources.Limits, r.Limits)
	}

	tmpfs := int32(0o400)
	mounts := []kube.VolumeMount{
		// PrivateTmp=
		{Name: "tmp", MountPath: "/tmp"},
		{Name: "bridge", MountPath: bridgeDir, ReadOnly: true},
		{Name: "bridge-secret", MountPath: bridgeSecretDir, ReadOnly: true},
	}
	volumes := []kube.Volume{
		{Name: "tmp", EmptyDir: &kube.EmptyDirVolumeSource{}},
		{Name: "bridge", EmptyDir: &kube.EmptyDirVolumeSource{}},
		{Name: "bridge-secret", Secret: &kube.SecretVolumeSource{SecretName: name, DefaultMode: &tmpfs,
			Items: []kube.KeyToPath{{Key: bridgeTokenKey, Path: "token"}}}},
	}
	if len(creds) > 0 {
		mounts = append(mounts, kube.VolumeMount{Name: "credentials", MountPath: credentialsDir, ReadOnly: true})
		volumes = append(volumes, kube.Volume{Name: "credentials", Secret: &kube.SecretVolumeSource{
			SecretName: name, DefaultMode: &tmpfs, Items: credItems}})
	}

	podSC := &kube.PodSecurityContext{
		RunAsNonRoot: ptr(true), RunAsUser: ptr(uid), RunAsGroup: ptr(uid), FSGroup: ptr(uid),
		// SystemCallFilter=@system-service, SystemCallArchitectures=native
		SeccompProfile: &kube.SeccompProfile{Type: "RuntimeDefault"},
	}
	if o.MCSLevel != "" || (o.AllowSELinuxType && b.SELinuxType != config.DefaultSELinuxType) {
		podSC.SELinuxOptions = &kube.SELinuxOptions{Level: o.MCSLevel}
		if o.AllowSELinuxType && b.SELinuxType != config.DefaultSELinuxType {
			podSC.SELinuxOptions.Type = b.SELinuxType
		}
	}

	deadline := int64(instanceRuntimeMax / time.Second) // RuntimeMaxSec=
	grace := int64(5)
	pod := kube.Pod{APIVersion: "v1", Kind: "Pod", Metadata: meta, Spec: kube.PodSpec{
		RestartPolicy:                 "Never", // the pool restarts instances, with its backoff
		ActiveDeadlineSeconds:         &deadline,
		TerminationGracePeriodSeconds: &grace,
		// No token of the instance's account and no other Services'
		// addresses: a server reaches nothing it is not given.
		AutomountServiceAccountToken: ptr(false),
		EnableServiceLinks:           ptr(false),
		SecurityContext:              podSC,
		InitContainers: []kube.Container{{
			Name: "bridge", Image: o.BridgeImage, ImagePullPolicy: o.ImagePullPolicy,
			Command:         []string{"/usr/bin/cp", bridgeBinary, bridgeDir + "/"},
			SecurityContext: restricted(),
			VolumeMounts:    []kube.VolumeMount{{Name: "bridge", MountPath: bridgeDir}},
			Resources:       &kube.ResourceRequirements{Limits: map[string]string{"memory": "32Mi"}},
		}},
		Containers: []kube.Container{{
			Name: "server", Image: b.Image, ImagePullPolicy: o.ImagePullPolicy,
			Command:         []string{bridgeDir + "/mcp-stdio-bridge"},
			Args:            args,
			Env:             env,
			Ports:           []kube.ContainerPort{{Name: "bridge", ContainerPort: BridgePort, Protocol: "TCP"}},
			Resources:       resources,
			SecurityContext: restricted(),
			VolumeMounts:    mounts,
		}},
		Volumes:      volumes,
		NodeSelector: maps.Clone(b.NodeSelector),
	}}
	for _, t := range b.Tolerations {
		pod.Spec.Tolerations = append(pod.Spec.Tolerations, kube.Toleration{Key: t.Key, Operator: t.Operator,
			Value: t.Value, Effect: t.Effect, TolerationSeconds: t.TolerationSeconds})
	}

	return &InstanceObjects{Pod: pod, Policy: instancePolicy(b, meta, o), Secret: secret}, nil
}

// restricted is a container's part of the sandbox: NoNewPrivileges=,
// ProtectSystem=strict, CapabilityBoundingSet= (empty).
func restricted() *kube.SecurityContext {
	return &kube.SecurityContext{
		AllowPrivilegeEscalation: ptr(false),
		Privileged:               ptr(false),
		ReadOnlyRootFilesystem:   ptr(true),
		RunAsNonRoot:             ptr(true),
		Capabilities:             &kube.Capabilities{Drop: []string{"ALL"}},
	}
}

// instancePolicy is the instance's NetworkPolicy: only the gateway's
// pods reach its bridge; without network (PrivateNetwork=,
// RestrictAddressFamilies=AF_UNIX) it reaches nothing, with network:
// true anything.
func instancePolicy(b *config.Backend, meta kube.ObjectMeta, o PodOptions) kube.NetworkPolicy {
	from := kube.NetworkPolicyPeer{PodSelector: &kube.LabelSelector{MatchLabels: maps.Clone(o.GatewayLabels)}}
	if o.GatewayNamespace != "" {
		from.NamespaceSelector = &kube.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": o.GatewayNamespace}}
	}
	egress := []kube.NetworkPolicyRule{}
	if b.Network {
		egress = append(egress, kube.NetworkPolicyRule{})
	}
	return kube.NetworkPolicy{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy", Metadata: meta,
		Spec: kube.NetworkPolicySpec{
			PodSelector: kube.LabelSelector{MatchLabels: map[string]string{LabelInstance: meta.Labels[LabelInstance]}},
			PolicyTypes: []string{"Ingress", "Egress"},
			Ingress: []kube.NetworkPolicyRule{{From: []kube.NetworkPolicyPeer{from},
				Ports: []kube.NetworkPolicyPort{{Protocol: "TCP", Port: BridgePort}}}},
			Egress: egress,
		}}
}

// InstanceName is the name of an instance's pod, Secret and
// NetworkPolicy: mcp-<server>-<id>, within a DNS label.
func InstanceName(server, id string) string {
	name := "mcp-" + server + "-" + id
	if len(name) > 63 {
		name = name[:63]
	}
	return strings.TrimRight(name, "-")
}

// InstanceUID is the uid an instance runs as (DynamicUser=): derived
// from its id, high, never root or a system account.
func InstanceUID(id string) int64 {
	var n uint64
	for _, c := range id {
		n = n*31 + uint64(c)
	}
	return instanceUIDBase + int64(n%instanceUIDs)
}

func ptr[T any](v T) *T { return &v }
