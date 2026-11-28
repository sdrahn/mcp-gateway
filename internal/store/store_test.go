package store

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/kube"
	"github.com/sdrahn/mcp-gateway/internal/kube/kubetest"
)

func testCollection(t *testing.T) (*Kubernetes, *kubetest.Secrets) {
	t.Helper()
	api := kubetest.NewSecrets(t)
	c, err := NewKubernetes(api.Client(), "gw", "grants")
	if err != nil {
		t.Fatal(err)
	}
	return c, api
}

func TestCollectionName(t *testing.T) {
	for _, name := range []string{"", "Grants", "grants_x", "-grants", "a"} {
		if _, err := NewKubernetes(&kube.Client{}, "gw", name); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
}

func TestKubernetesWrites(t *testing.T) {
	c, api := testCollection(t)
	ctx := context.Background()
	// Any name: the Secret's name is a digest of it.
	name := "g-1/Ä x"
	r, err := c.Create(ctx, name, []byte(`{"a":1}`))
	if err != nil || r.Version == "" {
		t.Fatalf("create: %v %+v", err, r)
	}
	if _, err := c.Create(ctx, name, []byte(`{}`)); !errors.Is(err, ErrExists) {
		t.Errorf("create again: %v", err)
	}
	// Another collection in the namespace is not listed.
	other, _ := NewKubernetes(api.Client(), "gw", "notices")
	if _, err := other.Create(ctx, name, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	recs, version, err := c.List(ctx)
	if err != nil || len(recs) != 1 || recs[0].Name != name || string(recs[0].Data) != `{"a":1}` || version == "" {
		t.Fatalf("list: %v %+v %q", err, recs, version)
	}
	r2, err := c.Update(ctx, Record{Name: name, Data: []byte(`{"a":2}`), Version: r.Version})
	if err != nil || r2.Version == r.Version {
		t.Fatalf("update: %v %+v", err, r2)
	}
	// The old version no longer updates nor deletes.
	if _, err := c.Update(ctx, Record{Name: name, Data: []byte(`{"a":3}`), Version: r.Version}); !errors.Is(err, ErrConflict) {
		t.Errorf("update with an old version: %v", err)
	}
	if err := c.Delete(ctx, name, r.Version); !errors.Is(err, ErrConflict) {
		t.Errorf("delete with an old version: %v", err)
	}
	if _, err := c.Update(ctx, Record{Name: "absent", Data: []byte(`{}`), Version: "1"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("update of a record not there: %v", err)
	}
	if err := c.Delete(ctx, name, r2.Version); err != nil {
		t.Errorf("delete: %v", err)
	}
	if err := c.Delete(ctx, name, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete again: %v", err)
	}
	if n := api.Len("gw"); n != 1 {
		t.Errorf("%d Secrets left, want the other collection's", n)
	}
}

// waitFor waits until cond holds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func decodeString(b []byte) (string, error) { return string(b), nil }

func runMirror(t *testing.T, c Collection) (*Mirror[string], *atomic.Int32) {
	t.Helper()
	var changes atomic.Int32
	m := &Mirror[string]{C: c, Decode: decodeString, MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond,
		OnChange: func() { changes.Add(1) }}
	if err := m.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return m, &changes
}

func value(m *Mirror[string], name string) (string, bool) {
	items, _ := m.Items()
	it, ok := items[name]
	return it.Value, ok
}

func TestMirrorFollows(t *testing.T) {
	c, api := testCollection(t)
	ctx := context.Background()
	if _, err := c.Create(ctx, "a", []byte("1")); err != nil {
		t.Fatal(err)
	}
	m, changes := runMirror(t, c)
	if v, ok := value(m, "a"); !ok || v != "1" || !m.Synced() {
		t.Fatalf("loaded %q %v", v, ok)
	}
	// Another writer's create, update and delete.
	other, _ := NewKubernetes(api.Client(), "gw", "grants")
	r, _ := other.Create(ctx, "b", []byte("2"))
	waitFor(t, "b", func() bool { v, _ := value(m, "b"); return v == "2" })
	_, _ = other.Update(ctx, Record{Name: "b", Data: []byte("3"), Version: r.Version})
	waitFor(t, "b updated", func() bool { v, _ := value(m, "b"); return v == "3" })
	_ = other.Delete(ctx, "a", "")
	waitFor(t, "a deleted", func() bool { _, ok := value(m, "a"); return !ok })
	if changes.Load() < 4 {
		t.Errorf("%d changes", changes.Load())
	}
}

func TestMirrorOwnDeleteStays(t *testing.T) {
	c, _ := testCollection(t)
	ctx := context.Background()
	m := &Mirror[string]{C: c, Decode: decodeString}
	r, _ := c.Create(ctx, "a", []byte("1"))
	m.Put(r, "1")
	_ = c.Delete(ctx, "a", r.Version)
	m.Deleted("a")
	// The watch's events from before the delete do not bring it back.
	m.apply(Event{Record: r})
	if _, ok := value(m, "a"); ok {
		t.Fatal("deleted record back from an older event")
	}
	// Nor does a list that still has it (it predates the delete).
	m.mu.Lock()
	m.deleted["stale"] = true
	m.mu.Unlock()
	if _, err := c.Create(ctx, "stale", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := m.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := value(m, "stale"); ok {
		t.Error("deleted record back from a list")
	}
	// The event of the delete ends the tombstone.
	m.apply(Event{Record: Record{Name: "a"}, Deleted: true})
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleted["a"] {
		t.Error("tombstone kept after the delete's event")
	}
}

func TestMirrorBrokenWatch(t *testing.T) {
	c, api := testCollection(t)
	ctx := context.Background()
	m, _ := runMirror(t, c)
	// A dropped watch, then a change while none runs: seen after listing
	// again.
	api.Compact()
	api.Break()
	other, _ := NewKubernetes(api.Client(), "gw", "grants")
	_, _ = other.Create(ctx, "a", []byte("1"))
	waitFor(t, "a after the watch broke", func() bool { v, _ := value(m, "a"); return v == "1" && m.Synced() })
}

// failing fails its lists and watches while fail is set.
type failing struct {
	Collection
	fail atomic.Bool
}

func (f *failing) List(ctx context.Context) ([]Record, string, error) {
	if f.fail.Load() {
		return nil, "", errors.New("no API server")
	}
	return f.Collection.List(ctx)
}

func (f *failing) Watch(ctx context.Context, version string, fn func(Event), bookmark func(string)) error {
	if f.fail.Load() {
		return errors.New("no API server")
	}
	return f.Collection.Watch(ctx, version, fn, bookmark)
}

func TestMirrorUnsynced(t *testing.T) {
	c, api := testCollection(t)
	f := &failing{Collection: c}
	m, _ := runMirror(t, f)
	f.fail.Store(true)
	// A watch that got past the check before fail was set may connect
	// only after a first Break.
	waitFor(t, "unsynced", func() bool { api.Break(); return !m.Synced() })
	f.fail.Store(false)
	waitFor(t, "synced again", m.Synced)
}

func TestMirrorExpired(t *testing.T) {
	c, api := testCollection(t)
	ctx := context.Background()
	m := &Mirror[string]{C: c, Decode: decodeString, MinBackoff: 10 * time.Millisecond}
	if err := m.Load(ctx); err != nil {
		t.Fatal(err)
	}
	// Changes, then compaction, before the watch starts: it starts from a
	// version too old, and the mirror lists again.
	other, _ := NewKubernetes(api.Client(), "gw", "grants")
	_, _ = other.Create(ctx, "a", []byte("1"))
	api.Compact()
	if err := c.Watch(ctx, m.version, func(Event) {}, nil); !errors.Is(err, ErrExpired) {
		t.Fatalf("watch from a compacted version: %v", err)
	}
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { m.Run(rctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitFor(t, "a listed again", func() bool { v, _ := value(m, "a"); return v == "1" && m.Synced() })
}
