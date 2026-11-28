package store

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"maps"
	"sync"
	"time"
)

// Table writes a map of records through to a collection, for state that
// was a file written whole at each change (pending approvals, notices,
// reviews): Save takes the whole map, and a writer of its own (Run)
// creates, updates and deletes the records that changed since the last
// save, with their versions. Saving does not wait for the store, so that
// a slow API server does not hold up the caller (which saves with its
// lock held); the writer keeps the latest map only, retries after
// errors, and lists the collection again when a record changed under it.
type Table struct {
	C   Collection
	Log *slog.Logger
	// MinBackoff and MaxBackoff bound the wait before retrying (default
	// 1s and 30s).
	MinBackoff, MaxBackoff time.Duration

	mu    sync.Mutex
	cond  *sync.Cond
	want  map[string][]byte // the latest map not written yet; nil: none
	saves int               // Save's count
	done  int               // the saves written
	kick  chan struct{}
	saved map[string]Record // as the writer last wrote or listed them
}

// Load lists the collection: the records' data by name. Call it once,
// before Run.
func (t *Table) Load(ctx context.Context) (map[string][]byte, error) {
	recs, _, err := t.C.List(ctx)
	if err != nil {
		return nil, err
	}
	saved := map[string]Record{}
	out := map[string][]byte{}
	for _, r := range recs {
		saved[r.Name] = r
		out[r.Name] = r.Data
	}
	t.init()
	t.mu.Lock()
	t.saved = saved
	t.mu.Unlock()
	return out, nil
}

func (t *Table) init() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cond == nil {
		t.cond = sync.NewCond(&t.mu)
		t.kick = make(chan struct{}, 1)
	}
}

// Save asks for the collection to be items, by name.
func (t *Table) Save(items map[string][]byte) {
	t.init()
	t.mu.Lock()
	t.want = maps.Clone(items)
	if t.want == nil {
		t.want = map[string][]byte{}
	}
	t.saves++
	t.mu.Unlock()
	select {
	case t.kick <- struct{}{}:
	default:
	}
}

// Flush waits until what was saved before it is written, or ctx ends.
func (t *Table) Flush(ctx context.Context) error {
	t.init()
	stop := context.AfterFunc(ctx, func() {
		t.mu.Lock()
		t.cond.Broadcast()
		t.mu.Unlock()
	})
	defer stop()
	t.mu.Lock()
	defer t.mu.Unlock()
	n := t.saves
	for t.done < n {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		t.cond.Wait()
	}
	return nil
}

// Run writes what is saved until ctx ends.
func (t *Table) Run(ctx context.Context) {
	t.init()
	minB, maxB := t.MinBackoff, t.MaxBackoff
	if minB <= 0 {
		minB = time.Second
	}
	if maxB < minB {
		maxB = max(30*time.Second, minB)
	}
	backoff := minB
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.kick:
		}
		for {
			t.mu.Lock()
			want, n := t.want, t.saves
			t.want = nil
			t.mu.Unlock()
			if want == nil {
				break
			}
			err := t.write(ctx, want)
			t.mu.Lock()
			if err == nil {
				t.done = max(t.done, n)
				t.cond.Broadcast()
			} else if t.want == nil {
				t.want = want // nothing newer: this again
			}
			t.mu.Unlock()
			if err == nil {
				backoff = minB
				continue
			}
			if ctx.Err() != nil {
				return
			}
			t.log().Warn("store: writing records failed; retrying", "err", err, "in", backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(2*backoff, maxB)
		}
	}
}

// write makes the collection want. A record that changed under the
// writer (another writer's, or a write whose answer was lost) has the
// collection listed again, and the write is tried anew.
func (t *Table) write(ctx context.Context, want map[string][]byte) error {
	t.mu.Lock()
	saved := maps.Clone(t.saved)
	t.mu.Unlock()
	var errs []error
	stale := false
	for name, data := range want {
		cur, ok := saved[name]
		var r Record
		var err error
		switch {
		case !ok:
			r, err = t.C.Create(ctx, name, data)
		case !bytes.Equal(cur.Data, data):
			r, err = t.C.Update(ctx, Record{Name: name, Data: data, Version: cur.Version})
		default:
			continue
		}
		if err != nil {
			stale = stale || errors.Is(err, ErrExists) || errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound)
			errs = append(errs, err)
			continue
		}
		saved[name] = r
	}
	for name, cur := range saved {
		if _, ok := want[name]; ok {
			continue
		}
		err := t.C.Delete(ctx, name, cur.Version)
		if err != nil && !errors.Is(err, ErrNotFound) {
			stale = stale || errors.Is(err, ErrConflict)
			errs = append(errs, err)
			continue
		}
		delete(saved, name)
	}
	if stale {
		if recs, _, err := t.C.List(ctx); err == nil {
			saved = map[string]Record{}
			for _, r := range recs {
				saved[r.Name] = r
			}
		}
	}
	t.mu.Lock()
	t.saved = saved
	t.mu.Unlock()
	return errors.Join(errs...)
}

func (t *Table) log() *slog.Logger {
	if t.Log != nil {
		return t.Log
	}
	return slog.Default()
}
