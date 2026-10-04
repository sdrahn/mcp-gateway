package signin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/oauth"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Key identifies a principal across sessions: how they connect, who
// vouches for them, and who they are.
type Key struct {
	Transport principal.Transport `json:"transport"`
	Issuer    string              `json:"iss,omitempty"`
	Sub       string              `json:"sub"`
	// UID is the principal's local uid (for the approver rules), if any.
	UID *uint32 `json:"uid,omitempty"`
}

// KeyOf returns p's key.
func KeyOf(p principal.Principal) Key {
	return Key{Transport: p.Transport, Issuer: p.Issuer, Sub: p.Sub, UID: p.UID}
}

func (k Key) id() string { return string(k.Transport) + "\x00" + k.Issuer + "\x00" + k.Sub }

// Same reports whether k and o are the same principal.
func (k Key) Same(o Key) bool { return k.id() == o.id() }

// Entry is a principal's sign-in to a server, as the store lists it:
// everything but the tokens.
type Entry struct {
	Server    string `json:"server"`
	Principal Key    `json:"principal"`
	// Resource is the server's url the tokens are bound to (RFC 8707);
	// empty in entries of 0.12.
	Resource string    `json:"resource,omitempty"`
	Since    time.Time `json:"since"`
	Expiry   time.Time `json:"expiry,omitzero"`
	Scope    string    `json:"scope,omitempty"`
	// Refreshable says whether there is a refresh token.
	Refreshable bool `json:"refreshable"`
}

// stored is an entry in the file: with its tokens, encrypted.
type stored struct {
	Entry
	Sealed []byte `json:"sealed"`
}

// Tokens are a principal's tokens for a server.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// clientEntry is a client registered at an authorization server.
type clientEntry struct {
	Server string `json:"server"`
	Issuer string `json:"issuer"`
	Sealed []byte `json:"sealed"`
}

type storeFile struct {
	Version int           `json:"version"`
	Entries []stored      `json:"entries"`
	Clients []clientEntry `json:"clients,omitempty"`
}

// Store keeps the principals' tokens, and registered clients, in
// state_dir/tokens.json, each encrypted with AES-256-GCM under the key in
// state_dir/tokens.key (made on first use), with the server and the
// principal (or the issuer) as associated data: an entry cannot be moved
// to another principal or server.
type Store struct {
	path string
	aead cipher.AEAD

	mu      sync.Mutex
	entries []stored
	clients []clientEntry
}

// OpenStore opens the store in dir.
func OpenStore(dir string) (*Store, error) {
	key, err := loadKey(filepath.Join(dir, "tokens.key"))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "tokens.json"), aead: aead}
	data, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		var f storeFile
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", s.path, err)
		}
		s.entries, s.clients = f.Entries, f.Clients
	}
	return s, nil
}

// loadKey reads the 32-byte key at path, making it first if there is
// none.
func loadKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			return loadKey(path) // made meanwhile
		}
		if err != nil {
			return nil, fmt.Errorf("token key: %w", err)
		}
		_, err = f.Write(key)
		if cErr := f.Close(); err == nil {
			err = cErr
		}
		if err != nil {
			_ = os.Remove(path)
			return nil, fmt.Errorf("token key: %w", err)
		}
		return key, nil
	}
	if err != nil {
		return nil, fmt.Errorf("token key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("token key %s: %d bytes, not 32", path, len(key))
	}
	return key, nil
}

func (s *Store) seal(v any, aad string) ([]byte, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, s.aead.NonceSize(), s.aead.NonceSize()+len(plain)+s.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plain, []byte(aad)), nil
}

func (s *Store) open(sealed []byte, aad string, v any) error {
	n := s.aead.NonceSize()
	if len(sealed) < n {
		return errors.New("signin: sealed entry too short")
	}
	plain, err := s.aead.Open(nil, sealed[:n], sealed[n:], []byte(aad))
	if err != nil {
		return fmt.Errorf("signin: cannot decrypt an entry (a different token key?): %w", err)
	}
	return json.Unmarshal(plain, v)
}

func tokenAAD(server string, k Key) string { return "token\x00" + server + "\x00" + k.id() }
func clientAAD(server, issuer string) string {
	return "client\x00" + server + "\x00" + issuer
}

// Get returns the principal's entry and tokens for server.
func (s *Store) Get(server string, k Key) (Entry, Tokens, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.find(server, k)
	if i < 0 {
		return Entry{}, Tokens{}, false, nil
	}
	e := s.entries[i]
	var t Tokens
	if err := s.open(e.Sealed, tokenAAD(server, k), &t); err != nil {
		return Entry{}, Tokens{}, false, err
	}
	return e.Entry, t, true, nil
}

func (s *Store) find(server string, k Key) int {
	return slices.IndexFunc(s.entries, func(e stored) bool { return e.Server == server && e.Principal.Same(k) })
}

// Put stores a token answer for the principal and server (at url
// resource): of a sign-in (since is now), or of a refresh (since is kept,
// and an answer without a refresh token keeps the old one).
func (s *Store) Put(server, resource string, k Key, t *oauth.Token, now time.Time, refresh bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := Entry{Server: server, Resource: resource, Principal: k, Since: now, Scope: t.Scope}
	tokens := Tokens{AccessToken: t.AccessToken, RefreshToken: t.RefreshToken}
	i := s.find(server, k)
	if !refresh {
		i = -1 // a new sign-in replaces the entry
		s.entries = slices.DeleteFunc(s.entries, func(e stored) bool { return e.Server == server && e.Principal.Same(k) })
	}
	if i >= 0 && t.RefreshToken == "" {
		var old Tokens
		if err := s.open(s.entries[i].Sealed, tokenAAD(server, k), &old); err == nil {
			tokens.RefreshToken = old.RefreshToken
		}
	}
	if i >= 0 && t.Scope == "" {
		e.Scope = s.entries[i].Scope
	}
	if !t.Expiry.IsZero() {
		e.Expiry = t.Expiry
	}
	e.Refreshable = tokens.RefreshToken != ""
	sealed, err := s.seal(tokens, tokenAAD(server, k))
	if err != nil {
		return err
	}
	if i >= 0 {
		e.Since = s.entries[i].Since
		s.entries[i] = stored{e, sealed}
	} else {
		s.entries = append(s.entries, stored{e, sealed})
	}
	return s.persist()
}

// Expire marks the principal's access token for server as expired (the
// server refused it), so that the next instance refreshes it first.
func (s *Store) Expire(server string, k Key, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.find(server, k)
	if i < 0 {
		return nil
	}
	s.entries[i].Expiry = now.Add(-time.Second)
	return s.persist()
}

// Delete removes the principal's sign-in to server and returns its
// tokens.
func (s *Store) Delete(server string, k Key) (Tokens, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.find(server, k)
	if i < 0 {
		return Tokens{}, false, nil
	}
	var t Tokens
	_ = s.open(s.entries[i].Sealed, tokenAAD(server, k), &t)
	s.entries = slices.Delete(s.entries, i, i+1)
	return t, true, s.persist()
}

// DeleteServer removes all sign-ins to server (its definition is gone).
func (s *Store) DeleteServer(server string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.entries)
	s.entries = slices.DeleteFunc(s.entries, func(e stored) bool { return e.Server == server })
	if len(s.entries) == n {
		return nil
	}
	return s.persist()
}

// List returns the sign-ins (without tokens), by server and principal.
func (s *Store) List() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Entry, len(s.entries))
	for i, e := range s.entries {
		out[i] = e.Entry
	}
	slices.SortFunc(out, func(a, b Entry) int {
		return strings.Compare(a.Server+"\x00"+a.Principal.id(), b.Server+"\x00"+b.Principal.id())
	})
	return out
}

// Client returns the client registered for server at issuer.
func (s *Store) Client(server, issuer string) (oauth.Client, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.clients {
		if c.Server == server && c.Issuer == issuer {
			var cl oauth.Client
			if s.open(c.Sealed, clientAAD(server, issuer), &cl) == nil {
				return cl, true
			}
		}
	}
	return oauth.Client{}, false
}

// PutClient stores the client registered for server at issuer.
func (s *Store) PutClient(server, issuer string, c oauth.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sealed, err := s.seal(c, clientAAD(server, issuer))
	if err != nil {
		return err
	}
	s.clients = slices.DeleteFunc(s.clients, func(c clientEntry) bool { return c.Server == server && c.Issuer == issuer })
	s.clients = append(s.clients, clientEntry{Server: server, Issuer: issuer, Sealed: sealed})
	return s.persist()
}

// persist writes the store atomically (mode 0600). Caller holds s.mu.
func (s *Store) persist() error {
	b, err := json.MarshalIndent(storeFile{Version: 1, Entries: s.entries, Clients: s.clients}, "", "  ")
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
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
