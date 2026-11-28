// Package replicas keeps track of the gateway's replicas
// (docs/architecture.md, section 5.12.5, D24): each holds a Lease of its
// own in the gateway's namespace, renewed every few seconds, with the
// address its peers reach it at; a replica whose Lease ran out is gone,
// and the others take over what it held.
package replicas

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/kube"
)

// Labels and annotations of the replicas' Leases.
const (
	ManagedByLabel    = "app.kubernetes.io/managed-by"
	ManagedBy         = "mcp-gateway"
	RoleLabel         = "mcp-gateway.io/role"
	RoleReplica       = "replica"
	AddressAnnotation = "mcp-gateway.io/address"
	leasePrefix       = "mcp-gateway-replica-"
	// DefaultDuration is how long a replica's Lease lasts unrenewed.
	DefaultDuration = 15 * time.Second
)

// Member is a replica as its Lease says.
type Member struct {
	Name    string
	Address string
	Expires time.Time
}

// Members is this replica's Lease and its view of the others'.
type Members struct {
	Client    *kube.Client
	Namespace string
	// Name is this replica's (its pod's), Address where its peers reach
	// it.
	Name, Address string
	// Duration is how long a Lease lasts unrenewed (DefaultDuration); it
	// is renewed, and the others listed, every third of it.
	Duration time.Duration
	Log      *slog.Logger
	Now      func() time.Time
	// OnChange, if set, is called when a replica came or went (not with
	// the lock held).
	OnChange func()

	mu      sync.Mutex
	members map[string]Member
	version string // of this replica's Lease
	// live are the live replicas' names at the last refresh, for
	// OnChange.
	live []string
}

func (m *Members) duration() time.Duration {
	if m.Duration > 0 {
		return m.Duration
	}
	return DefaultDuration
}

func (m *Members) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Members) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

func (m *Members) leasePath(name string) string {
	return kube.LeasesPath(m.Namespace) + "/" + leasePrefix + name
}

func (m *Members) lease(version string, acquired *kube.MicroTime) kube.Lease {
	now := kube.NewMicroTime(m.now())
	if acquired == nil {
		acquired = now
	}
	return kube.Lease{APIVersion: "coordination.k8s.io/v1", Kind: "Lease",
		Metadata: kube.ObjectMeta{Name: leasePrefix + m.Name, Namespace: m.Namespace, ResourceVersion: version,
			Labels:      map[string]string{ManagedByLabel: ManagedBy, RoleLabel: RoleReplica},
			Annotations: map[string]string{AddressAnnotation: m.Address}},
		Spec: kube.LeaseSpec{HolderIdentity: m.Name, LeaseDurationSeconds: int(m.duration() / time.Second),
			AcquireTime: acquired, RenewTime: now}}
}

// Join takes this replica's Lease and lists the others: at the start,
// before the replica serves.
func (m *Members) Join(ctx context.Context) error {
	if m.Name == "" {
		return fmt.Errorf("replicas: this replica has no name")
	}
	if err := m.renew(ctx); err != nil {
		return fmt.Errorf("replicas: the replica's Lease: %w", err)
	}
	return m.refresh(ctx)
}

// renew writes this replica's Lease: created, or renewed with its
// version (taken again if someone else wrote it meanwhile).
func (m *Members) renew(ctx context.Context) error {
	m.mu.Lock()
	version := m.version
	m.mu.Unlock()
	var out kube.Lease
	if version != "" {
		err := m.Client.Update(ctx, m.leasePath(m.Name), m.lease(version, nil), &out)
		if err == nil {
			m.setVersion(out.Metadata.ResourceVersion)
			return nil
		}
		if !kube.IsConflict(err) && !kube.IsNotFound(err) {
			return err
		}
	}
	var cur kube.Lease
	switch err := m.Client.Get(ctx, m.leasePath(m.Name), &cur); {
	case kube.IsNotFound(err):
		if err := m.Client.Create(ctx, kube.LeasesPath(m.Namespace), m.lease("", nil), &out); err != nil {
			return err
		}
	case err != nil:
		return err
	default:
		// A Lease of this name from an earlier run, or written by someone
		// else meanwhile: this replica's now.
		if err := m.Client.Update(ctx, m.leasePath(m.Name), m.lease(cur.Metadata.ResourceVersion, nil), &out); err != nil {
			return err
		}
	}
	m.setVersion(out.Metadata.ResourceVersion)
	return nil
}

func (m *Members) setVersion(v string) {
	m.mu.Lock()
	m.version = v
	m.mu.Unlock()
}

// refresh lists the replicas' Leases.
func (m *Members) refresh(ctx context.Context) error {
	var list kube.LeaseList
	if err := m.Client.List(ctx, kube.LeasesPath(m.Namespace), ManagedByLabel+"="+ManagedBy+","+RoleLabel+"="+RoleReplica, &list); err != nil {
		return err
	}
	members := map[string]Member{}
	for _, l := range list.Items {
		if l.Spec.HolderIdentity == "" || l.Metadata.Name != leasePrefix+l.Spec.HolderIdentity {
			continue
		}
		members[l.Spec.HolderIdentity] = Member{Name: l.Spec.HolderIdentity, Address: l.Metadata.Annotations[AddressAnnotation],
			Expires: l.Spec.Expires()}
	}
	m.mu.Lock()
	m.members = members
	live := m.liveNames()
	changed := !slices.Equal(live, m.live)
	m.live = live
	m.mu.Unlock()
	if m.OnChange != nil && changed {
		m.OnChange()
	}
	return nil
}

// liveNames returns the live replicas' names, sorted. Caller holds m.mu.
func (m *Members) liveNames() []string {
	now := m.now()
	var out []string
	for name, mb := range m.members {
		if name == m.Name || mb.Expires.After(now) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// Run renews this replica's Lease and lists the others until ctx ends,
// then gives the Lease up, so that the others take over at once.
func (m *Members) Run(ctx context.Context) {
	tick := time.NewTicker(m.duration() / 3)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			m.leave()
			return
		case <-tick.C:
		}
		rctx, cancel := context.WithTimeout(ctx, m.duration()/3)
		if err := m.renew(rctx); err != nil && ctx.Err() == nil {
			m.log().Warn("replicas: renewing this replica's Lease failed", "err", err)
		}
		if err := m.refresh(rctx); err != nil && ctx.Err() == nil {
			m.log().Warn("replicas: listing the replicas failed", "err", err)
		}
		cancel()
	}
}

// leave deletes this replica's Lease.
func (m *Members) leave() {
	m.mu.Lock()
	version := m.version
	m.mu.Unlock()
	if version == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Client.DeleteVersion(ctx, m.leasePath(m.Name), version); err != nil && !kube.IsNotFound(err) {
		m.log().Warn("replicas: giving up this replica's Lease failed; the others take over when it runs out", "err", err)
	}
}

// Live returns the replicas whose Lease has not run out, this one among
// them, by name.
func (m *Members) Live() map[string]Member {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]Member{}
	for _, name := range m.liveNames() {
		mb, ok := m.members[name]
		if !ok {
			mb = Member{Name: name, Address: m.Address}
		}
		out[name] = mb
	}
	return out
}

// IsLive reports whether the replica called name holds its Lease; this
// replica always does.
func (m *Members) IsLive(name string) bool {
	if name == m.Name {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	mb, ok := m.members[name]
	return ok && mb.Expires.After(m.now())
}
