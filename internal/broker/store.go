package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Store keeps grants. "duration" grants are persisted to a JSON file, so
// they survive restarts; "session" grants live as long as their session.
// ("once" grants are never stored.)
type Store struct {
	path string
	now  func() time.Time

	mu     sync.Mutex
	grants []pep.Grant
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants = append(s.grants, g)
	if g.Scope == "duration" {
		return s.persist()
	}
	return nil
}

// Match returns the unexpired grants of p for server/tool. Session grants
// only match in their own session.
func (s *Store) Match(p principal.Principal, server, tool string) []pep.Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []pep.Grant
	for _, g := range s.grants {
		if s.expired(g) || g.Sub != p.Sub || g.Issuer != p.Issuer || g.Server != server || g.Tool != tool {
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
	defer s.mu.Unlock()
	s.prune()
	return append([]pep.Grant(nil), s.grants...)
}

// Get returns the grant with id.
func (s *Store) Get(id string) (pep.Grant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.grants {
		if g.ID == id && !s.expired(g) {
			return g, true
		}
	}
	return pep.Grant{}, false
}

// Revoke removes the grant with id.
func (s *Store) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, g := range s.grants {
		if g.ID == id {
			s.grants = append(s.grants[:i], s.grants[i+1:]...)
			if g.Scope == "duration" {
				return s.persist()
			}
			return nil
		}
	}
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

// persist writes the unexpired duration grants atomically. Caller holds
// s.mu.
func (s *Store) persist() error {
	if s.path == "" {
		return nil
	}
	var durable []pep.Grant
	for _, g := range s.grants {
		if g.Scope == "duration" && !s.expired(g) {
			durable = append(durable, g)
		}
	}
	b, err := json.MarshalIndent(durable, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".grants-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(b, '\n')); err != nil {
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
	return os.Rename(tmp.Name(), s.path)
}
