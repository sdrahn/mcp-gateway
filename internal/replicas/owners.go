package replicas

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/kube"
)

// RoleOwner is the role label of the principals' Leases.
const (
	RoleOwner   = "owner"
	ownerPrefix = "mcp-gateway-owner-"
	// DefaultOwnerDuration is how long a principal's Lease lasts
	// unrenewed; while the principal is busy or used, its owner renews it.
	DefaultOwnerDuration = 2 * time.Minute
	// foreignTTL is how long the owner of another replica's principal is
	// remembered before the Lease is read again.
	foreignTTL = 5 * time.Second
)

// Owners decides which replica serves a principal (docs/architecture.md,
// section 5.12.5, D24): the holder of the principal's Lease, a
// Lease per principal key, taken by the first replica a request reaches
// when none holds it or its holder is gone (its replica Lease ran out),
// and kept while the principal is busy there (Busy) or was used within
// Idle; then given up, so that the principal's next request may go to any
// replica. The Lease's name is a digest of the key: who the principals
// are is not in the cluster's objects.
type Owners struct {
	Client    *kube.Client
	Namespace string
	Members   *Members
	// Duration is how long a principal's Lease lasts unrenewed
	// (DefaultOwnerDuration); renewed every third of it.
	Duration time.Duration
	// Idle is how long a principal not busy is held after its last use
	// (supervisor.idle_timeout).
	Idle time.Duration
	// Busy, if set, reports the principals that have instances,
	// sessions or tasks here, by key.
	Busy func() map[string]bool
	Now  func() time.Time

	mu      sync.Mutex
	held    map[string]*holding // by key, this replica's
	foreign map[string]foreign  // by key, other replicas'
}

type holding struct {
	version  string
	acquired *kube.MicroTime
	used     time.Time
	trans    int
}

type foreign struct {
	holder string
	seen   time.Time
}

func (o *Owners) duration() time.Duration {
	if o.Duration > 0 {
		return o.Duration
	}
	return DefaultOwnerDuration
}

func (o *Owners) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// LeaseName returns the name of key's Lease.
func LeaseName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return ownerPrefix + hex.EncodeToString(sum[:16])
}

func (o *Owners) path(key string) string {
	return kube.LeasesPath(o.Namespace) + "/" + LeaseName(key)
}

func (o *Owners) lease(key, version string, acquired *kube.MicroTime, trans int) kube.Lease {
	now := kube.NewMicroTime(o.now())
	if acquired == nil {
		acquired = now
	}
	return kube.Lease{APIVersion: "coordination.k8s.io/v1", Kind: "Lease",
		Metadata: kube.ObjectMeta{Name: LeaseName(key), Namespace: o.Namespace, ResourceVersion: version,
			Labels: map[string]string{ManagedByLabel: ManagedBy, RoleLabel: RoleOwner}},
		Spec: kube.LeaseSpec{HolderIdentity: o.Members.Name, LeaseDurationSeconds: int(o.duration() / time.Second),
			AcquireTime: acquired, RenewTime: now, LeaseTransitions: trans}}
}

// ErrNoOwner is returned when the principal's Lease cannot be read or
// taken: the request is not served rather than served by two replicas.
var ErrNoOwner = errors.New("replicas: no owner for the principal")

// Owner returns the replica that serves key: this one (Members.Name),
// taking the principal's Lease if none holds it, or another. The use is
// noted for this replica's principals.
func (o *Owners) Owner(ctx context.Context, key string) (string, error) {
	now := o.now()
	o.mu.Lock()
	if h, ok := o.held[key]; ok {
		h.used = now
		o.mu.Unlock()
		return o.Members.Name, nil
	}
	if f, ok := o.foreign[key]; ok && now.Sub(f.seen) < foreignTTL && o.Members.IsLive(f.holder) {
		o.mu.Unlock()
		return f.holder, nil
	}
	o.mu.Unlock()
	for range 3 {
		holder, err := o.claim(ctx, key)
		if err == nil {
			return holder, nil
		}
		if !kube.IsConflict(err) && !kube.IsAlreadyExists(err) {
			return "", fmt.Errorf("%w: %v", ErrNoOwner, err)
		}
		// Another replica wrote the Lease meanwhile: read it again.
	}
	return "", ErrNoOwner
}

// claim reads key's Lease and takes it if no live replica holds it.
func (o *Owners) claim(ctx context.Context, key string) (string, error) {
	var cur kube.Lease
	err := o.Client.Get(ctx, o.path(key), &cur)
	var out kube.Lease
	switch {
	case kube.IsNotFound(err):
		if err := o.Client.Create(ctx, kube.LeasesPath(o.Namespace), o.lease(key, "", nil, 0), &out); err != nil {
			return "", err
		}
		o.hold(key, out, 0)
		return o.Members.Name, nil
	case err != nil:
		return "", err
	}
	holder := cur.Spec.HolderIdentity
	switch {
	case holder == o.Members.Name:
		// Held here before (this replica's restart under its name, or a
		// renewal that this replica's memory lost): renew it as its own.
		if err := o.Client.Update(ctx, o.path(key), o.lease(key, cur.Metadata.ResourceVersion, cur.Spec.AcquireTime, cur.Spec.LeaseTransitions), &out); err != nil {
			return "", err
		}
		o.hold(key, out, cur.Spec.LeaseTransitions)
		return o.Members.Name, nil
	case holder != "" && cur.Spec.Expires().After(o.now()) && o.Members.IsLive(holder):
		o.mu.Lock()
		if o.foreign == nil {
			o.foreign = map[string]foreign{}
		}
		o.foreign[key] = foreign{holder, o.now()}
		o.mu.Unlock()
		return holder, nil
	}
	// Its holder is gone, or it ran out: this replica's now.
	trans := cur.Spec.LeaseTransitions + 1
	if err := o.Client.Update(ctx, o.path(key), o.lease(key, cur.Metadata.ResourceVersion, nil, trans), &out); err != nil {
		return "", err
	}
	o.hold(key, out, trans)
	return o.Members.Name, nil
}

func (o *Owners) hold(key string, l kube.Lease, trans int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.held == nil {
		o.held = map[string]*holding{}
	}
	o.held[key] = &holding{version: l.Metadata.ResourceVersion, acquired: l.Spec.AcquireTime, used: o.now(), trans: trans}
	delete(o.foreign, key)
}

// Held returns the keys this replica holds.
func (o *Owners) Held() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]string, 0, len(o.held))
	for k := range o.held {
		out = append(out, k)
	}
	return out
}

// Run renews the Leases of the principals that are busy here or were used
// within Idle, and gives up the others, until ctx ends; then gives up all.
func (o *Owners) Run(ctx context.Context) {
	tick := time.NewTicker(o.duration() / 3)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			o.releaseAll()
			return
		case <-tick.C:
		}
		o.renew(ctx)
	}
}

// renew renews or gives up each held Lease.
func (o *Owners) renew(ctx context.Context) {
	var busy map[string]bool
	if o.Busy != nil {
		busy = o.Busy()
	}
	now := o.now()
	o.mu.Lock()
	keys := make(map[string]holding, len(o.held))
	for k, h := range o.held {
		keys[k] = *h
	}
	o.mu.Unlock()
	for key, h := range keys {
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if !busy[key] && now.Sub(h.used) > o.Idle {
			o.release(rctx, key, h.version)
			cancel()
			continue
		}
		var out kube.Lease
		err := o.Client.Update(rctx, o.path(key), o.lease(key, h.version, h.acquired, h.trans), &out)
		cancel()
		switch {
		case err == nil:
			o.mu.Lock()
			if cur, ok := o.held[key]; ok {
				cur.version = out.Metadata.ResourceVersion
			}
			o.mu.Unlock()
		case kube.IsConflict(err) || kube.IsNotFound(err):
			// Taken by another replica (this one was thought gone): it
			// serves the principal now.
			o.forget(key)
		default:
			o.Members.log().Warn("replicas: renewing a principal's Lease failed", "lease", LeaseName(key), "err", err)
		}
	}
}

func (o *Owners) forget(key string) {
	o.mu.Lock()
	delete(o.held, key)
	o.mu.Unlock()
}

// release gives key's Lease up.
func (o *Owners) release(ctx context.Context, key, version string) {
	o.forget(key)
	if err := o.Client.DeleteVersion(ctx, o.path(key), version); err != nil && !kube.IsNotFound(err) && !kube.IsConflict(err) {
		o.Members.log().Warn("replicas: giving up a principal's Lease failed", "lease", LeaseName(key), "err", err)
	}
}

func (o *Owners) releaseAll() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o.mu.Lock()
	keys := make(map[string]string, len(o.held))
	for k, h := range o.held {
		keys[k] = h.version
	}
	o.mu.Unlock()
	for k, v := range keys {
		o.release(ctx, k, v)
	}
}
