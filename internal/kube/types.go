// Package kube holds the few Kubernetes API objects the gateway's
// Kubernetes launcher creates (docs/architecture.md, section 5.12.3): a
// Pod, a NetworkPolicy and a Secret per instance, with the API's own
// JSON field names. Only the fields the launcher sets are here; the
// gateway speaks the API's REST interface with them, without client-go.
package kube

// ObjectMeta is an object's name, namespace, labels and annotations.
type ObjectMeta struct {
	Name string `json:"name"`
	// UID is set by the API server; OwnerReferences make an object go
	// with its owner (an instance's Secret and NetworkPolicy with its pod).
	UID             string            `json:"uid,omitempty"`
	OwnerReferences []OwnerReference  `json:"ownerReferences,omitempty"`
	Namespace       string            `json:"namespace,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Annotations     map[string]string `json:"annotations,omitempty"`
	// ResourceVersion is set by the API server; an update or a delete
	// that names it succeeds only on that version (compare-and-set).
	ResourceVersion string `json:"resourceVersion,omitempty"`
}

// ListMeta is a list's resource version, from which a watch starts.
type ListMeta struct {
	ResourceVersion string `json:"resourceVersion,omitempty"`
}

// OwnerReference names an object's owner.
type OwnerReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
}

// Pod is a v1 Pod.
type Pod struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Metadata   ObjectMeta `json:"metadata"`
	Spec       PodSpec    `json:"spec"`
	Status     *PodStatus `json:"status,omitempty"`
}

// PodStatus is what the launcher reads of a pod's status.
type PodStatus struct {
	Phase                 string            `json:"phase,omitempty"`
	Reason                string            `json:"reason,omitempty"`
	Message               string            `json:"message,omitempty"`
	PodIP                 string            `json:"podIP,omitempty"`
	InitContainerStatuses []ContainerStatus `json:"initContainerStatuses,omitempty"`
	ContainerStatuses     []ContainerStatus `json:"containerStatuses,omitempty"`
}

// ContainerStatus is a container's state.
type ContainerStatus struct {
	Name  string         `json:"name"`
	State ContainerState `json:"state"`
}

// ContainerState is waiting, running or terminated.
type ContainerState struct {
	Waiting    *ContainerStateWaiting    `json:"waiting,omitempty"`
	Terminated *ContainerStateTerminated `json:"terminated,omitempty"`
}

// ContainerStateWaiting says why a container does not run yet.
type ContainerStateWaiting struct {
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// ContainerStateTerminated says how a container ended.
type ContainerStateTerminated struct {
	ExitCode int32  `json:"exitCode"`
	Reason   string `json:"reason,omitempty"`
	Message  string `json:"message,omitempty"`
}

// PodList is a list of pods.
type PodList struct {
	Items []Pod `json:"items"`
}

// PodSpec is the part of a pod's spec the launcher sets.
type PodSpec struct {
	RestartPolicy                 string              `json:"restartPolicy"`
	ActiveDeadlineSeconds         *int64              `json:"activeDeadlineSeconds,omitempty"`
	TerminationGracePeriodSeconds *int64              `json:"terminationGracePeriodSeconds,omitempty"`
	AutomountServiceAccountToken  *bool               `json:"automountServiceAccountToken"`
	EnableServiceLinks            *bool               `json:"enableServiceLinks"`
	HostNetwork                   bool                `json:"hostNetwork"`
	HostPID                       bool                `json:"hostPID"`
	HostIPC                       bool                `json:"hostIPC"`
	SecurityContext               *PodSecurityContext `json:"securityContext,omitempty"`
	InitContainers                []Container         `json:"initContainers,omitempty"`
	Containers                    []Container         `json:"containers"`
	Volumes                       []Volume            `json:"volumes,omitempty"`
	NodeSelector                  map[string]string   `json:"nodeSelector,omitempty"`
	Tolerations                   []Toleration        `json:"tolerations,omitempty"`
}

// PodSecurityContext is a pod's security context.
type PodSecurityContext struct {
	RunAsNonRoot   *bool           `json:"runAsNonRoot,omitempty"`
	RunAsUser      *int64          `json:"runAsUser,omitempty"`
	RunAsGroup     *int64          `json:"runAsGroup,omitempty"`
	FSGroup        *int64          `json:"fsGroup,omitempty"`
	SeccompProfile *SeccompProfile `json:"seccompProfile,omitempty"`
	SELinuxOptions *SELinuxOptions `json:"seLinuxOptions,omitempty"`
}

// SeccompProfile names a seccomp profile.
type SeccompProfile struct {
	Type string `json:"type"`
}

// SELinuxOptions is a pod's SELinux label.
type SELinuxOptions struct {
	Type  string `json:"type,omitempty"`
	Level string `json:"level,omitempty"`
}

// Container is a container of a pod.
type Container struct {
	Name            string                `json:"name"`
	Image           string                `json:"image"`
	ImagePullPolicy string                `json:"imagePullPolicy,omitempty"`
	Command         []string              `json:"command,omitempty"`
	Args            []string              `json:"args,omitempty"`
	Env             []EnvVar              `json:"env,omitempty"`
	Ports           []ContainerPort       `json:"ports,omitempty"`
	Resources       *ResourceRequirements `json:"resources,omitempty"`
	SecurityContext *SecurityContext      `json:"securityContext,omitempty"`
	VolumeMounts    []VolumeMount         `json:"volumeMounts,omitempty"`
}

// EnvVar is a container's environment variable.
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ContainerPort is a port a container listens on.
type ContainerPort struct {
	Name          string `json:"name,omitempty"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol,omitempty"`
}

// ResourceRequirements are a container's requests and limits.
type ResourceRequirements struct {
	Requests map[string]string `json:"requests,omitempty"`
	Limits   map[string]string `json:"limits,omitempty"`
}

// SecurityContext is a container's security context.
type SecurityContext struct {
	AllowPrivilegeEscalation *bool         `json:"allowPrivilegeEscalation"`
	Privileged               *bool         `json:"privileged"`
	ReadOnlyRootFilesystem   *bool         `json:"readOnlyRootFilesystem"`
	RunAsNonRoot             *bool         `json:"runAsNonRoot,omitempty"`
	Capabilities             *Capabilities `json:"capabilities,omitempty"`
}

// Capabilities are added to and dropped from a container's.
type Capabilities struct {
	Add  []string `json:"add,omitempty"`
	Drop []string `json:"drop,omitempty"`
}

// VolumeMount mounts a volume into a container.
type VolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
}

// Volume is a pod's volume: an emptyDir or a Secret.
type Volume struct {
	Name     string                `json:"name"`
	EmptyDir *EmptyDirVolumeSource `json:"emptyDir,omitempty"`
	Secret   *SecretVolumeSource   `json:"secret,omitempty"`
}

// EmptyDirVolumeSource is an emptyDir volume.
type EmptyDirVolumeSource struct {
	Medium    string `json:"medium,omitempty"`
	SizeLimit string `json:"sizeLimit,omitempty"`
}

// SecretVolumeSource mounts a Secret's keys as files.
type SecretVolumeSource struct {
	SecretName  string      `json:"secretName"`
	DefaultMode *int32      `json:"defaultMode,omitempty"`
	Items       []KeyToPath `json:"items,omitempty"`
}

// KeyToPath mounts one key of a Secret as a file.
type KeyToPath struct {
	Key  string `json:"key"`
	Path string `json:"path"`
}

// Toleration lets a pod onto a tainted node.
type Toleration struct {
	Key               string `json:"key,omitempty"`
	Operator          string `json:"operator,omitempty"`
	Value             string `json:"value,omitempty"`
	Effect            string `json:"effect,omitempty"`
	TolerationSeconds *int64 `json:"tolerationSeconds,omitempty"`
}

// Secret is a v1 Secret, its data as strings (stringData, written only)
// or bytes (data, as the API server returns it).
type Secret struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   ObjectMeta        `json:"metadata"`
	Type       string            `json:"type"`
	Immutable  bool              `json:"immutable"`
	StringData map[string]string `json:"stringData,omitempty"`
	Data       map[string][]byte `json:"data,omitempty"`
}

// SecretList is a v1 SecretList.
type SecretList struct {
	Metadata ListMeta `json:"metadata"`
	Items    []Secret `json:"items"`
}

// NetworkPolicy is a networking.k8s.io/v1 NetworkPolicy.
type NetworkPolicy struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   ObjectMeta        `json:"metadata"`
	Spec       NetworkPolicySpec `json:"spec"`
}

// NetworkPolicySpec selects pods and lists the traffic they may have.
type NetworkPolicySpec struct {
	PodSelector LabelSelector       `json:"podSelector"`
	PolicyTypes []string            `json:"policyTypes"`
	Ingress     []NetworkPolicyRule `json:"ingress"`
	Egress      []NetworkPolicyRule `json:"egress"`
}

// NetworkPolicyRule is an ingress or egress rule: traffic from or to
// the peers, on the ports (none: any). An empty rule allows all.
type NetworkPolicyRule struct {
	From  []NetworkPolicyPeer `json:"from,omitempty"`
	To    []NetworkPolicyPeer `json:"to,omitempty"`
	Ports []NetworkPolicyPort `json:"ports,omitempty"`
}

// NetworkPolicyPeer selects pods, by their labels and their namespace's.
type NetworkPolicyPeer struct {
	PodSelector       *LabelSelector `json:"podSelector,omitempty"`
	NamespaceSelector *LabelSelector `json:"namespaceSelector,omitempty"`
}

// NetworkPolicyPort is a port of a rule.
type NetworkPolicyPort struct {
	Protocol string `json:"protocol,omitempty"`
	Port     int    `json:"port"`
}

// LabelSelector matches labels.
type LabelSelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}
