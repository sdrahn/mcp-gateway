package broker

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/store"
)

// Store keeps grants. "duration" grants are persisted to a JSON file, so
// they survive restarts; "session" grants live as long as their session.
// "once" grants are stored (and persisted) only for approvals decided
// while no call was waiting (see Broker.Resolve); the next matching call
// takes and consumes one (TakeOnce).
//
// With a shared store (OpenSharedStore; docs/architecture.md, section
// 5.12.5) the persisted grants are records of a collection instead of the
// file, one each, mirrored in memory: a once grant is taken by deleting
// its record with its version, so that two takers cannot both have it,
// and while the mirror is not synced they count as absent (the call asks
// instead of being allowed on stale grants).
type Store struct {
	path string
	now  func() time.Time
	// shared holds the persisted grants with a shared store.
	shared *store.Mirror[pep.Grant]
	log    *slog.Logger

	mu sync.Mutex
	// grants are all of them with a file, the session grants with a
	// shared store.
	grants []pep.Grant
	// dropping are the expired grants being deleted from the shared
	// store.
	dropping map[string]bool
}

// OpenStore loads the grants file at path ("" keeps grants in memory
// only).
func OpenStore(path string, now func() time.Time) (*Store, error) {
	s := &Store{path: path, now: now}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &s.grants); err != nil {
		return nil, fmt.Errorf("broker: reading %s: %w", path, err)
	}
	s.mu.Lock()
	s.prune()
	s.mu.Unlock()
	return s, nil
}

// sharedBackoff is the first wait before listing a collection again
// after its watch broke (tests shorten it).
var sharedBackoff = time.Second

// OpenSharedStore keeps the persisted grants in c: listed now, then
// watched until ctx ends.
func OpenSharedStore(ctx context.Context, c store.Collection, now func() time.Time, log *slog.Logger) (*Store, error) {
	if log == nil {
		log = slog.Default()
	}
	m := &store.Mirror[pep.Grant]{C: c, Log: log, MinBackoff: sharedBackoff, MaxBackoff: 30 * sharedBackoff, Decode: func(b []byte) (pep.Grant, error) {
		var g pep.Grant
		err := json.Unmarshal(b, &g)
		return g, err
	}}
	if err := m.Load(ctx); err != nil {
		return nil, fmt.Errorf("broker: grants: %w", err)
	}
	go m.Run(ctx)
	return &Store{now: now, shared: m, log: log}, nil
}

// sharedGrants returns the unexpired persisted grants of the shared
// store, the earliest to expire first, with their versions; none while
// the mirror is not synced, unless all is set (for listing).
func (s *Store) sharedGrants(all bool) []store.Item[pep.Grant] {
	items, synced := s.shared.Items()
	if !synced && !all {
		return nil
	}
	out := make([]store.Item[pep.Grant], 0, len(items))
	var expired []string
	for name, it := range items {
		if s.expired(it.Value) {
			expired = append(expired, name)
			continue
		}
		out = append(out, it)
	}
	slices.SortFunc(out, func(a, b store.Item[pep.Grant]) int {
		return cmp.Or(cmp.Compare(a.Value.Expires, b.Value.Expires), cmp.Compare(a.Value.ID, b.Value.ID))
	})
	if len(expired) > 0 {
		s.dropExpired(expired)
	}
	return out
}

// dropExpired deletes expired grants from the shared store in the
// background, each once at a time (any replica may; one gone already is
// done).
func (s *Store) dropExpired(names []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dropping == nil {
		s.dropping = map[string]bool{}
	}
	for _, name := range names {
		if s.dropping[name] {
			continue
		}
		s.dropping[name] = true
		go func() {
			err := s.shared.C.Delete(context.Background(), name, "")
			if err == nil || errors.Is(err, store.ErrNotFound) {
				s.shared.Deleted(name)
			} else {
				s.log.Warn("deleting an expired grant from the store failed", "grant", name, "err", err)
			}
			s.mu.Lock()
			delete(s.dropping, name)
			s.mu.Unlock()
		}()
	}
}

func (s *Store) expired(g pep.Grant) bool {
	exp, err := time.Parse(time.RFC3339, g.Expires)
	return err != nil || !exp.After(s.now())
}

// prune drops expired grants. Caller holds s.mu.
func (s *Store) prune() {
	kept := s.grants[:0]
	for _, g := range s.grants {
		if !s.expired(g) {
			kept = append(kept, g)
		}
	}
	s.grants = kept
}

// Add stores g.
func (s *Store) Add(g pep.Grant) error {
	if s.shared != nil && persisted(g) {
		data, err := json.Marshal(g)
		if err != nil {
			return err
		}
		r, err := s.shared.C.Create(context.Background(), g.ID, data)
		if err != nil {
			return fmt.Errorf("broker: storing grant %s: %w", g.ID, err)
		}
		s.shared.Put(r, g)
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants = append(s.grants, g)
	if persisted(g) {
		return s.persist()
	}
	return nil
}

func persisted(g pep.Grant) bool { return g.Scope == "duration" || g.Scope == "once" }

// TakeOnce removes and returns the oldest unexpired stored "once" grant of
// p for server/tool.
func (s *Store) TakeOnce(p principal.Principal, server, tool string) (pep.Grant, bool) {
	if s.shared != nil {
		return s.takeShared(p, server, tool)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, g := range s.grants {
		if g.Scope != "once" || s.expired(g) || g.Sub != p.Sub || g.Issuer != p.Issuer || g.Server != server || g.Tool != tool {
			continue
		}
		s.grants = append(s.grants[:i], s.grants[i+1:]...)
		_ = s.persist()
		return g, true
	}
	return pep.Grant{}, false
}

// takeShared takes a once grant from the shared store: the one whose
// delete with its version succeeds is the taker's.
func (s *Store) takeShared(p principal.Principal, server, tool string) (pep.Grant, bool) {
	for _, it := range s.sharedGrants(false) {
		g := it.Value
		if g.Scope != "once" || g.Sub != p.Sub || g.Issuer != p.Issuer || g.Server != server || g.Tool != tool {
			continue
		}
		err := s.shared.C.Delete(context.Background(), g.ID, it.Version)
		switch {
		case err == nil:
			s.shared.Deleted(g.ID)
			return g, true
		case errors.Is(err, store.ErrNotFound):
			s.shared.Deleted(g.ID) // taken by someone else
		case errors.Is(err, store.ErrConflict):
			// changed since: the mirror has the new version soon
		default:
			s.log.Warn("taking a grant from the store failed", "grant", g.ID, "err", err)
			return pep.Grant{}, false
		}
	}
	return pep.Grant{}, false
}

// Match returns the unexpired grants of p for server/tool. Session grants
// only match in their own session; stored "once" grants are left out
// (TakeOnce consumes them).
func (s *Store) Match(p principal.Principal, server, tool string) []pep.Grant {
	out := s.matchLocal(p, server, tool)
	if s.shared != nil {
		for _, it := range s.sharedGrants(false) {
			if g := it.Value; g.Sub == p.Sub && g.Issuer == p.Issuer && g.Server == server && g.Tool == tool && g.Scope != "once" {
				out = append(out, g)
			}
		}
	}
	return out
}

// matchLocal is Match of the grants in memory.
func (s *Store) matchLocal(p principal.Principal, server, tool string) []pep.Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []pep.Grant
	for _, g := range s.grants {
		if s.expired(g) || g.Sub != p.Sub || g.Issuer != p.Issuer || g.Server != server || g.Tool != tool || g.Scope == "once" {
			continue
		}
		if g.Scope == "session" && g.SessionID != p.SessionID {
			continue
		}
		out = append(out, g)
	}
	return out
}

// List returns all unexpired grants.
func (s *Store) List() []pep.Grant {
	s.mu.Lock()
	s.prune()
	out := append([]pep.Grant(nil), s.grants...)
	s.mu.Unlock()
	if s.shared != nil {
		for _, it := range s.sharedGrants(true) {
			out = append(out, it.Value)
		}
	}
	return out
}

// Get returns the grant with id.
func (s *Store) Get(id string) (pep.Grant, bool) {
	s.mu.Lock()
	for _, g := range s.grants {
		if g.ID == id && !s.expired(g) {
			s.mu.Unlock()
			return g, true
		}
	}
	s.mu.Unlock()
	if s.shared != nil {
		items, _ := s.shared.Items()
		if it, ok := items[id]; ok && !s.expired(it.Value) {
			return it.Value, true
		}
	}
	return pep.Grant{}, false
}

// Revoke removes the grant with id.
func (s *Store) Revoke(id string) error {
	s.mu.Lock()
	for i, g := range s.grants {
		if g.ID == id {
			s.grants = append(s.grants[:i], s.grants[i+1:]...)
			var err error
			if persisted(g) {
				err = s.persist()
			}
			s.mu.Unlock()
			return err
		}
	}
	s.mu.Unlock()
	if s.shared == nil {
		return nil
	}
	// Not only what the mirror has: it may not be synced.
	err := s.shared.C.Delete(context.Background(), id, "")
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("broker: revoking grant %s: %w", id, err)
	}
	s.shared.Deleted(id)
	return nil
}

// EndSession drops the grants of a session.
func (s *Store) EndSession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.grants[:0]
	for _, g := range s.grants {
		if g.Scope != "session" || g.SessionID != sessionID {
			kept = append(kept, g)
		}
	}
	s.grants = kept
}

// persist writes the unexpired duration and stored once grants
// atomically. Caller holds s.mu.
func (s *Store) persist() error {
	if s.path == "" {
		return nil
	}
	var durable []pep.Grant
	for _, g := range s.grants {
		if persisted(g) && !s.expired(g) {
			durable = append(durable, g)
		}
	}
	b, err := json.MarshalIndent(durable, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, append(b, '\n'))
}

// writeFileAtomic replaces path with data (mode 0600).
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
