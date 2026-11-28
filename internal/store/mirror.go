package store

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"sync"
	"time"
)

// Item is a record of a mirror, decoded.
type Item[T any] struct {
	Value   T
	Version string
}

// Mirror keeps a collection in memory, decoded: listed at Load, then
// watched (Run). While the watch is broken and the collection not listed
// again, it is not synced: what it holds may be stale, and callers that
// decide with it treat it as absent (grants count as none, D24).
//
// A writer tells the mirror what it wrote (Put) and deleted (Deleted),
// so that it sees its own writes at once. A record it deleted is not
// brought back by an event or a list that predates the delete.
type Mirror[T any] struct {
	C      Collection
	Decode func([]byte) (T, error)
	Log    *slog.Logger
	// OnChange, if set, is called after the records changed (not with
	// the mirror's lock held).
	OnChange func()
	// MinBackoff and MaxBackoff bound the wait before listing again after
	// an error (default 1s and 30s).
	MinBackoff, MaxBackoff time.Duration

	mu      sync.Mutex
	items   map[string]Item[T]
	deleted map[string]bool
	synced  bool
	version string
}

// Load lists the collection: the first time, before Run.
func (m *Mirror[T]) Load(ctx context.Context) error {
	recs, version, err := m.C.List(ctx)
	if err != nil {
		return err
	}
	items := map[string]Item[T]{}
	for _, r := range recs {
		v, err := m.Decode(r.Data)
		if err != nil {
			m.log().Warn("store: record not read", "name", r.Name, "err", err)
			continue
		}
		items[r.Name] = Item[T]{v, r.Version}
	}
	m.mu.Lock()
	for name := range m.deleted {
		if _, ok := items[name]; ok {
			// Listed before this mirror's delete took effect.
			delete(items, name)
		} else {
			delete(m.deleted, name)
		}
	}
	m.items, m.version, m.synced = items, version, true
	m.mu.Unlock()
	m.changed()
	return nil
}

// Run watches the collection until ctx ends, listing it again when the
// watch broke.
func (m *Mirror[T]) Run(ctx context.Context) {
	minB, maxB := m.MinBackoff, m.MaxBackoff
	if minB <= 0 {
		minB = time.Second
	}
	if maxB < minB {
		maxB = max(30*time.Second, minB)
	}
	backoff := minB
	for ctx.Err() == nil {
		m.mu.Lock()
		version, synced := m.version, m.synced
		m.mu.Unlock()
		var err error
		if !synced {
			err = m.Load(ctx)
		}
		if err == nil {
			err = m.C.Watch(ctx, version, m.apply, m.bookmark)
			if err == nil {
				backoff = minB
				continue // the store ended the watch: watch again
			}
		}
		if ctx.Err() != nil {
			return
		}
		m.mu.Lock()
		m.synced = false
		m.mu.Unlock()
		if !errors.Is(err, ErrExpired) {
			m.log().Warn("store: watch broke; listing again", "err", err, "in", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(2*backoff, maxB)
		}
	}
}

func (m *Mirror[T]) apply(ev Event) {
	m.mu.Lock()
	m.version = ev.Record.Version
	name := ev.Record.Name
	changed := false
	switch {
	case ev.Deleted:
		delete(m.deleted, name)
		if _, ok := m.items[name]; ok {
			delete(m.items, name)
			changed = true
		}
	case m.deleted[name]:
		// An event from before this mirror's delete.
	default:
		v, err := m.Decode(ev.Record.Data)
		if err != nil {
			m.log().Warn("store: record not read", "name", name, "err", err)
			break
		}
		m.items[name] = Item[T]{v, ev.Record.Version}
		changed = true
	}
	m.mu.Unlock()
	if changed {
		m.changed()
	}
}

func (m *Mirror[T]) bookmark(version string) {
	m.mu.Lock()
	m.version = version
	m.mu.Unlock()
}

// Items returns the records by name, and whether the mirror is synced.
func (m *Mirror[T]) Items() (map[string]Item[T], bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return maps.Clone(m.items), m.synced
}

// Synced reports whether the mirror follows the collection.
func (m *Mirror[T]) Synced() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.synced
}

// Put records a write of this process's (Create or Update returned r).
func (m *Mirror[T]) Put(r Record, v T) {
	m.mu.Lock()
	delete(m.deleted, r.Name)
	if m.items == nil {
		m.items = map[string]Item[T]{}
	}
	m.items[r.Name] = Item[T]{v, r.Version}
	m.mu.Unlock()
	m.changed()
}

// Deleted records a delete of this process's: the record is gone, and
// stays gone whatever an older event or list says.
func (m *Mirror[T]) Deleted(name string) {
	m.mu.Lock()
	if m.deleted == nil {
		m.deleted = map[string]bool{}
	}
	m.deleted[name] = true
	delete(m.items, name)
	m.mu.Unlock()
	m.changed()
}

func (m *Mirror[T]) changed() {
	if m.OnChange != nil {
		m.OnChange()
	}
}

func (m *Mirror[T]) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}
