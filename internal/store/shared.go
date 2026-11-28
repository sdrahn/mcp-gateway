package store

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"
)

// Shared is a collection several writers, the gateway's replicas, keep
// records of one kind in (pending approvals, notices, reviews, the
// clients seen; docs/architecture.md, section 5.12.5): each writes and
// deletes its own, named <replica>/<id>, through a table of its own, and
// follows everyone's through a mirror. A writer that is gone leaves its
// records to be adopted by a live one (Adopt).
type Shared struct {
	C       Collection
	Replica string
	Log     *slog.Logger
	// MinBackoff and MaxBackoff are the table's and the mirror's.
	MinBackoff, MaxBackoff time.Duration
	// OnChange, if set, is called after the records the mirror follows
	// changed (not with any lock of the caller's held).
	OnChange func()

	table  *Table
	mirror *Mirror[[]byte]
}

// Owned is a record of another writer's: its writer ("" for a record of
// a single writer, before there were several), its name, data and
// version.
type Owned struct {
	Replica string
	Name    string
	Data    []byte
	Version string
}

func (s *Shared) prefix() string { return s.Replica + "/" }

// Load lists the collection: this writer's records by id. Call it once,
// before Run.
func (s *Shared) Load(ctx context.Context) (map[string][]byte, error) {
	s.table = &Table{C: s.C, Log: s.Log, Prefix: s.prefix(), MinBackoff: s.MinBackoff, MaxBackoff: s.MaxBackoff}
	s.mirror = &Mirror[[]byte]{C: s.C, Log: s.Log, MinBackoff: s.MinBackoff, MaxBackoff: s.MaxBackoff,
		Decode: func(b []byte) ([]byte, error) { return b, nil }, OnChange: s.OnChange}
	if err := s.mirror.Load(ctx); err != nil {
		return nil, err
	}
	return s.table.Load(ctx)
}

// Run writes this writer's records and follows the others' until ctx
// ends.
func (s *Shared) Run(ctx context.Context) {
	go s.mirror.Run(ctx)
	s.table.Run(ctx)
}

// Save makes this writer's records items, by id.
func (s *Shared) Save(items map[string][]byte) { s.table.Save(items) }

// Flush waits until what was saved is written.
func (s *Shared) Flush(ctx context.Context) error { return s.table.Flush(ctx) }

// Others returns the other writers' records, by id, and whether the
// mirror follows the collection.
func (s *Shared) Others() (map[string]Owned, bool) {
	items, synced := s.mirror.Items()
	out := map[string]Owned{}
	for name, it := range items {
		replica, id, ok := strings.Cut(name, "/")
		if !ok {
			replica, id = "", name // a single writer's, adopted as a gone one's
		}
		if replica == s.Replica {
			continue
		}
		out[id] = Owned{Replica: replica, Name: name, Data: it.Value, Version: it.Version}
	}
	return out, synced
}

// Adopt takes over the records of writers that are gone (live says which
// are not), and those of a single writer before there were several: each copied under this writer's name, then the original
// deleted with its version; a record another writer adopted first, or
// that its writer changed meanwhile, is left. It returns the adopted
// records by id, for the caller to add to what it saves.
func (s *Shared) Adopt(ctx context.Context, live func(replica string) bool) (map[string][]byte, error) {
	others, _ := s.Others()
	out := map[string][]byte{}
	var errs []error
	for id, o := range others {
		if o.Replica != "" && live(o.Replica) {
			continue
		}
		mine, err := s.C.Create(ctx, s.prefix()+id, o.Data)
		if err != nil && !errors.Is(err, ErrExists) {
			errs = append(errs, err)
			continue
		}
		if err := s.C.Delete(ctx, o.Name, o.Version); err != nil {
			// Adopted by another writer, or changed: not this writer's.
			if errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) {
				if mine.Version != "" {
					_ = s.C.Delete(ctx, s.prefix()+id, mine.Version)
				}
				continue
			}
			errs = append(errs, err)
			continue
		}
		s.mirror.Deleted(o.Name)
		if mine.Version != "" {
			s.table.remember(mine)
		}
		out[id] = o.Data
	}
	return out, errors.Join(errs...)
}
