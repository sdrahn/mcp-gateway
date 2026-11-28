package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/kube"
)

// Labels and annotations of the gateway's records.
const (
	ManagedByLabel  = "app.kubernetes.io/managed-by"
	ManagedBy       = "mcp-gateway"
	CollectionLabel = "mcp-gateway.io/collection"
	NameAnnotation  = "mcp-gateway.io/name"
	// SecretType is the type of the Secrets that hold records.
	SecretType = "mcp-gateway.io/record"
	// dataKey is the key of a record's data in its Secret.
	dataKey = "record"
	// watchTimeout is how long one watch request lasts before the API
	// server ends it and the mirror watches again.
	watchTimeout = 5 * time.Minute
)

// collectionName is a collection's name: part of its Secrets' names and
// a label value.
var collectionName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)

// Kubernetes is a collection kept as Secrets in a namespace, one per
// record (docs/architecture.md, section 5.12.5): labelled with the
// collection, named after it and a digest of the record's name (which
// may be anything), the name itself in an annotation. Secrets because
// records hold call arguments and tokens.
type Kubernetes struct {
	Client     *kube.Client
	Namespace  string
	Collection string
	// Timeout bounds each request but watches (default 10s).
	Timeout time.Duration
}

// NewKubernetes returns the collection named collection in namespace.
func NewKubernetes(c *kube.Client, namespace, collection string) (*Kubernetes, error) {
	if !collectionName.MatchString(collection) {
		return nil, fmt.Errorf("store: %q is not a collection name", collection)
	}
	return &Kubernetes{Client: c, Namespace: namespace, Collection: collection, Timeout: 10 * time.Second}, nil
}

func (k *Kubernetes) selector() string {
	return ManagedByLabel + "=" + ManagedBy + "," + CollectionLabel + "=" + k.Collection
}

// SecretName returns the name of the Secret of the record name.
func (k *Kubernetes) SecretName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "mcp-gateway-" + k.Collection + "-" + hex.EncodeToString(sum[:16])
}

func (k *Kubernetes) path(name string) string {
	return kube.SecretsPath(k.Namespace) + "/" + k.SecretName(name)
}

func (k *Kubernetes) ctx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, k.Timeout)
}

func (k *Kubernetes) secret(name string, data []byte, version string) kube.Secret {
	return kube.Secret{APIVersion: "v1", Kind: "Secret", Type: SecretType,
		Metadata: kube.ObjectMeta{Name: k.SecretName(name), Namespace: k.Namespace, ResourceVersion: version,
			Labels:      map[string]string{ManagedByLabel: ManagedBy, CollectionLabel: k.Collection},
			Annotations: map[string]string{NameAnnotation: name}},
		Data: map[string][]byte{dataKey: data}}
}

// record returns s as a record; ok false if s is not one of k's.
func (k *Kubernetes) record(s kube.Secret) (Record, bool) {
	name, ok := s.Metadata.Annotations[NameAnnotation]
	if !ok || s.Metadata.Labels[CollectionLabel] != k.Collection || s.Metadata.Name != k.SecretName(name) {
		return Record{}, false
	}
	return Record{Name: name, Data: s.Data[dataKey], Version: s.Metadata.ResourceVersion}, true
}

// storeErr maps the API server's answers to the store's errors.
func storeErr(err error) error {
	switch {
	case err == nil:
		return nil
	case kube.IsAlreadyExists(err):
		return fmt.Errorf("%w: %v", ErrExists, err)
	case kube.IsNotFound(err):
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	case kube.IsConflict(err):
		return fmt.Errorf("%w: %v", ErrConflict, err)
	case kube.IsGone(err):
		return fmt.Errorf("%w: %v", ErrExpired, err)
	}
	return err
}

func (k *Kubernetes) List(ctx context.Context) ([]Record, string, error) {
	ctx, cancel := k.ctx(ctx)
	defer cancel()
	var list kube.SecretList
	if err := k.Client.List(ctx, kube.SecretsPath(k.Namespace), k.selector(), &list); err != nil {
		return nil, "", storeErr(err)
	}
	var out []Record
	for _, s := range list.Items {
		if r, ok := k.record(s); ok {
			out = append(out, r)
		}
	}
	return out, list.Metadata.ResourceVersion, nil
}

func (k *Kubernetes) Create(ctx context.Context, name string, data []byte) (Record, error) {
	ctx, cancel := k.ctx(ctx)
	defer cancel()
	var out kube.Secret
	if err := k.Client.Create(ctx, kube.SecretsPath(k.Namespace), k.secret(name, data, ""), &out); err != nil {
		return Record{}, storeErr(err)
	}
	return Record{Name: name, Data: data, Version: out.Metadata.ResourceVersion}, nil
}

func (k *Kubernetes) Update(ctx context.Context, r Record) (Record, error) {
	if r.Version == "" {
		return Record{}, errors.New("store: update without a version")
	}
	ctx, cancel := k.ctx(ctx)
	defer cancel()
	var out kube.Secret
	if err := k.Client.Update(ctx, k.path(r.Name), k.secret(r.Name, r.Data, r.Version), &out); err != nil {
		return Record{}, storeErr(err)
	}
	return Record{Name: r.Name, Data: r.Data, Version: out.Metadata.ResourceVersion}, nil
}

func (k *Kubernetes) Delete(ctx context.Context, name, version string) error {
	ctx, cancel := k.ctx(ctx)
	defer cancel()
	if version != "" {
		return storeErr(k.Client.DeleteVersion(ctx, k.path(name), version))
	}
	// Whatever its version: the one it has now, again if it changes
	// meanwhile (kube's Delete would hide that it was gone).
	for {
		var s kube.Secret
		if err := k.Client.Get(ctx, k.path(name), &s); err != nil {
			return storeErr(err)
		}
		err := k.Client.DeleteVersion(ctx, k.path(name), s.Metadata.ResourceVersion)
		if !kube.IsConflict(err) || ctx.Err() != nil {
			return storeErr(err)
		}
	}
}

func (k *Kubernetes) Watch(ctx context.Context, version string, fn func(Event), bookmark func(string)) error {
	err := k.Client.Watch(ctx, kube.SecretsPath(k.Namespace), k.selector(), version, watchTimeout, func(ev kube.WatchEvent) error {
		var s kube.Secret
		if err := json.Unmarshal(ev.Object, &s); err != nil {
			return fmt.Errorf("store: watch: %w", err)
		}
		if ev.Type == "BOOKMARK" {
			if bookmark != nil {
				bookmark(s.Metadata.ResourceVersion)
			}
			return nil
		}
		r, ok := k.record(s)
		if !ok {
			return nil
		}
		switch ev.Type {
		case "ADDED", "MODIFIED":
			fn(Event{Record: r})
		case "DELETED":
			fn(Event{Record: r, Deleted: true})
		}
		return nil
	})
	return storeErr(err)
}
