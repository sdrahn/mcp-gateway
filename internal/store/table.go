package store

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"maps"
	"strings"
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
	// Prefix, if set, is this writer's part of a collection shared by
	// several (Shared): its records are named Prefix+id, and the table
	// writes, deletes and loads those only. Names passed in and returned
	// are the ids.
	Prefix string
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
	saved := t.own(recs)
	out := map[string][]byte{}
	for name, r := range saved {
		out[strings.TrimPrefix(name, t.Prefix)] = r.Data
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

// own returns the records of recs that are this table's, by name.
func (t *Table) own(recs []Record) map[string]Record {
	out := map[string]Record{}
	for _, r := range recs {
		if strings.HasPrefix(r.Name, t.Prefix) {
			out[r.Name] = r
		}
	}
	return out
}

// Save asks for the collection (this table's part of it) to be items, by
// id.
func (t *Table) Save(items map[string][]byte) {
	t.init()
	want := make(map[string][]byte, len(items))
	for id, data := range items {
		want[t.Prefix+id] = data
	}
	t.mu.Lock()
	t.want = want
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
			saved = t.own(recs)
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

// remember records r as written by this table (adopted from another
// writer: Shared.Adopt).
func (t *Table) remember(r Record) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.saved == nil {
		t.saved = map[string]Record{}
	}
	t.saved[r.Name] = r
}
