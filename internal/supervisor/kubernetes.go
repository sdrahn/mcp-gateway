package supervisor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/kube"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// DefaultPodStartTimeout bounds how long an instance's pod may take to
// run (scheduling, the image pull) before its start fails.
const DefaultPodStartTimeout = 2 * time.Minute

// Kubernetes starts instances as pods of their own in a namespace of
// theirs (docs/architecture.md, section 5.12.3): the pod, its
// NetworkPolicy and Secret (InstancePod), the Secret and NetworkPolicy
// owned by the pod so that they go with it; then it waits for the pod to
// run and connects to its mcp-stdio-bridge.
type Kubernetes struct {
	Client  *kube.Client
	Options PodOptions
	// MCS allocates an instance's category pair, for its SELinux level
	// (nil: none).
	MCS          *MCSAllocator
	StartTimeout time.Duration
	Log          *slog.Logger
	// readFile reads a credential (os.ReadFile outside tests).
	readFile func(string) ([]byte, error)
	// poll is how often a starting pod is looked at.
	poll time.Duration
	// dial connects to a pod's bridge (DialBridge outside tests).
	dial func(ctx context.Context, addr, token string) (io.ReadWriteCloser, error)
}

// Start implements Launcher.
func (k *Kubernetes) Start(ctx context.Context, b *config.Backend, p principal.Principal, id string) (Instance, error) {
	creds, err := k.credentials(b)
	if err != nil {
		return nil, err
	}
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	o := k.Options
	var pair string
	if k.MCS != nil {
		if pair, err = k.MCS.Allocate(); err != nil {
			return nil, err
		}
		o.MCSLevel = "s0:" + pair
	}
	release := func() {
		if pair != "" {
			k.MCS.Release(pair)
		}
	}
	objs, err := InstancePod(b, p, id, o, creds, token)
	if err != nil {
		release()
		return nil, err
	}
	ns, name := o.Namespace, objs.Pod.Metadata.Name
	timeout := k.StartTimeout
	if timeout <= 0 {
		timeout = DefaultPodStartTimeout
	}
	sctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var created kube.Pod
	if err := k.Client.Create(sctx, kube.PodsPath(ns), objs.Pod, &created); err != nil {
		release()
		return nil, fmt.Errorf("server %s: creating its pod: %w", b.Name, err)
	}
	inst := &kubeInstance{k: k, name: ns + "/" + name, pod: kube.PodsPath(ns) + "/" + name, release: release}
	owner := []kube.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: name, UID: created.Metadata.UID}}
	// The policy before the Secret: the pod cannot start without its
	// Secret, so it never runs without its policy.
	objs.Policy.Metadata.OwnerReferences = owner
	objs.Secret.Metadata.OwnerReferences = owner
	if err := k.Client.Create(sctx, kube.NetworkPoliciesPath(ns), objs.Policy, nil); err != nil {
		inst.remove()
		return nil, fmt.Errorf("server %s: creating its NetworkPolicy: %w", b.Name, err)
	}
	if err := k.Client.Create(sctx, kube.SecretsPath(ns), objs.Secret, nil); err != nil {
		inst.remove()
		return nil, fmt.Errorf("server %s: creating its Secret: %w", b.Name, err)
	}
	ip, err := k.waitRunning(sctx, inst.pod)
	if err != nil {
		inst.remove()
		return nil, fmt.Errorf("server %s: pod %s: %w", b.Name, inst.name, err)
	}
	dial := k.dial
	if dial == nil {
		dial = DialBridge
	}
	conn, err := dial(sctx, net.JoinHostPort(ip, strconv.Itoa(BridgePort)), token)
	if err != nil {
		inst.remove()
		return nil, fmt.Errorf("server %s: pod %s: %w", b.Name, inst.name, err)
	}
	inst.conn = conn
	if k.Log != nil {
		k.Log.Info("pod started", "server", b.Name, "pod", inst.name, "ip", ip)
	}
	return inst, nil
}

// credentials reads the definition's credentials: no systemd reads them
// for the instance in a cluster, the gateway puts them in its Secret.
func (k *Kubernetes) credentials(b *config.Backend) (map[string]string, error) {
	creds, err := b.ParseCredentials()
	if err != nil {
		return nil, err
	}
	read := k.readFile
	if read == nil {
		read = os.ReadFile
	}
	out := map[string]string{}
	for _, c := range creds {
		data, err := read(c.Path)
		if err != nil {
			return nil, fmt.Errorf("server %s: credential %s: %w", b.Name, c.Name, err)
		}
		out[c.Name] = string(data)
	}
	return out, nil
}

// waitRunning waits for the pod at path to run and returns its address;
// a pod that ended, or a container that cannot start (an image that does
// not pull, a configuration error), fails at once with the reason.
func (k *Kubernetes) waitRunning(ctx context.Context, path string) (string, error) {
	poll := k.poll
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	var last string
	for {
		var pod kube.Pod
		if err := k.Client.Get(ctx, path, &pod); err != nil {
			if ctx.Err() != nil {
				return "", fmt.Errorf("not running in time (%s)", last)
			}
			return "", err
		}
		st := pod.Status
		if st == nil {
			st = &kube.PodStatus{}
		}
		switch st.Phase {
		case "Running":
			if st.PodIP != "" {
				return st.PodIP, nil
			}
		case "Succeeded", "Failed":
			return "", fmt.Errorf("ended before it ran: %s", podReason(st))
		}
		if reason := stuck(st); reason != "" {
			return "", errors.New(reason)
		}
		last = st.Phase + " " + podReason(st)
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("not running in time (%s)", strings.TrimSpace(last))
		case <-time.After(poll):
		}
	}
}

// stuck is the reason a container waits that waiting does not cure.
func stuck(st *kube.PodStatus) string {
	for _, cs := range append(append([]kube.ContainerStatus{}, st.InitContainerStatuses...), st.ContainerStatuses...) {
		if w := cs.State.Waiting; w != nil {
			switch w.Reason {
			case "ErrImagePull", "ImagePullBackOff", "InvalidImageName", "CreateContainerConfigError", "CreateContainerError":
				return fmt.Sprintf("container %s: %s: %s", cs.Name, w.Reason, w.Message)
			}
		}
	}
	return ""
}

func podReason(st *kube.PodStatus) string {
	for _, cs := range append(append([]kube.ContainerStatus{}, st.InitContainerStatuses...), st.ContainerStatuses...) {
		if t := cs.State.Terminated; t != nil && t.ExitCode != 0 {
			return fmt.Sprintf("container %s exited %d %s %s", cs.Name, t.ExitCode, t.Reason, t.Message)
		}
		if w := cs.State.Waiting; w != nil && w.Reason != "" {
			return fmt.Sprintf("container %s %s", cs.Name, w.Reason)
		}
	}
	return strings.TrimSpace(st.Reason + " " + st.Message)
}

// Cleanup deletes the pods earlier runs of the gateway left (their
// instances ended with them); their Secrets and NetworkPolicies go with
// them.
func (k *Kubernetes) Cleanup(ctx context.Context) error {
	return k.Client.DeleteCollection(ctx, kube.PodsPath(k.Options.Namespace), LabelManagedBy+"="+managedBy)
}

// Reap deletes the pods of replicas that are gone (live reports which
// are not), and those that name no replica (left by a gateway of one
// replica): with several replicas, each deletes what the others left,
// instead of everything at its start. Their Secrets and NetworkPolicies
// go with them. It returns the replicas whose pods it deleted ("" for
// those without a replica).
func (k *Kubernetes) Reap(ctx context.Context, live func(replica string) bool) ([]string, error) {
	var list kube.PodList
	if err := k.Client.List(ctx, kube.PodsPath(k.Options.Namespace), LabelManagedBy+"="+managedBy, &list); err != nil {
		return nil, err
	}
	gone := map[string]bool{}
	for _, p := range list.Items {
		if r := p.Metadata.Labels[LabelReplica]; r == "" || !live(r) {
			gone[r] = true
		}
	}
	var out []string
	for _, r := range slices.Sorted(maps.Keys(gone)) {
		sel := LabelManagedBy + "=" + managedBy + "," + LabelReplica + "=" + r
		if r == "" {
			sel = LabelManagedBy + "=" + managedBy + ",!" + LabelReplica
		}
		if err := k.Client.DeleteCollection(ctx, kube.PodsPath(k.Options.Namespace), sel); err != nil {
			return out, err
		}
		out = append(out, r)
	}
	return out, nil
}

// kubeInstance is an instance in its pod.
type kubeInstance struct {
	k       *Kubernetes
	name    string
	pod     string
	conn    io.ReadWriteCloser
	release func()
	once    sync.Once
}

func (i *kubeInstance) Read(p []byte) (int, error)  { return i.conn.Read(p) }
func (i *kubeInstance) Write(p []byte) (int, error) { return i.conn.Write(p) }
func (i *kubeInstance) Name() string                { return i.name }

// Close closes the connection, which ends the server (the bridge closes
// its stdin), and deletes the pod.
func (i *kubeInstance) Close() error {
	err := i.conn.Close()
	i.remove()
	return err
}

// remove deletes the pod (its Secret and NetworkPolicy go with it) and
// releases its category pair, once.
func (i *kubeInstance) remove() {
	i.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := i.k.Client.Delete(ctx, i.pod, 5); err != nil && i.k.Log != nil {
			i.k.Log.Warn("pod not deleted", "pod", i.name, "err", err)
		}
		i.release()
	})
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Split starts instances of servers that speak HTTP (their connectors)
// with HTTP, and those of stdio servers with Stdio: container mode with
// the Kubernetes launcher.
type Split struct {
	HTTP, Stdio Launcher
}

// Start implements Launcher.
func (s Split) Start(ctx context.Context, b *config.Backend, p principal.Principal, id string) (Instance, error) {
	if b.URL != "" {
		return s.HTTP.Start(ctx, b, p, id)
	}
	return s.Stdio.Start(ctx, b, p, id)
}

// Check asks the API server for the instances' pods, as the launcher
// does, and returns how many there are: whether the gateway's account
// reaches the API server and may list pods in the namespace.
func (k *Kubernetes) Check(ctx context.Context) (int, error) {
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := k.Client.List(ctx, kube.PodsPath(k.Options.Namespace), LabelManagedBy+"="+managedBy, &list); err != nil {
		return 0, err
	}
	return len(list.Items), nil
}
