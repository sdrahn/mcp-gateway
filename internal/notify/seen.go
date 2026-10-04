package notify

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// maxSeen bounds the names Seen keeps; past it, new names are not added.
const maxSeen = 10000

// Seen remembers the local users who connected to the gateway or used
// its control API (Cockpit), in a file in the state directory. Approval
// mail asks NSS for their primary group by name (getent passwd NAME),
// which needs no enumeration: SSSD and LDAP often do not enumerate users,
// so the users whose primary group an approver group is cannot be found
// otherwise.
type Seen struct {
	path string

	mu    sync.Mutex
	names map[string]bool
}

// seenFile is the file's format.
type seenFile struct {
	Version int      `json:"version"`
	Names   []string `json:"names"`
}

// LoadSeen reads the names remembered in path; a missing file is empty.
func LoadSeen(path string) (*Seen, error) {
	s := &Seen{path: path, names: map[string]bool{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	var f seenFile
	if err := json.Unmarshal(b, &f); err != nil {
		return s, fmt.Errorf("%s: %w", path, err)
	}
	for _, n := range f.Names {
		if seenName(n) {
			s.names[n] = true
		}
	}
	return s, nil
}

// Add remembers name and writes the file if it is new. A nil Seen
// remembers nothing.
func (s *Seen) Add(name string) error {
	if s == nil || !seenName(name) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.names[name] || len(s.names) >= maxSeen {
		return nil
	}
	s.names[name] = true
	b, err := json.Marshal(seenFile{Version: 1, Names: s.sorted()})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".seen-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// seenName accepts account names (validName) that cannot be taken for
// an option.
func seenName(n string) bool { return validName(n) && !strings.HasPrefix(n, "-") }

// Names returns the names remembered, sorted.
func (s *Seen) Names() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sorted()
}

func (s *Seen) sorted() []string {
	names := make([]string, 0, len(s.names))
	for n := range s.names {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}
