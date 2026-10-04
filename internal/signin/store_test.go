package signin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/oauth"
)

func TestStore(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	alice := Key{Transport: "unix", Sub: "alice"}
	bob := Key{Transport: "http", Issuer: "https://idp", Sub: "bob"}
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	if err := s.Put("tickets", alice, &oauth.Token{AccessToken: "at-a", RefreshToken: "rt-a", Scope: "read", Expiry: now.Add(time.Hour)}, now, false); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("tickets", bob, &oauth.Token{AccessToken: "at-b"}, now, false); err != nil {
		t.Fatal(err)
	}
	// A refresh without a refresh token keeps the old one and the time of
	// the sign-in.
	if err := s.Put("tickets", alice, &oauth.Token{AccessToken: "at-a2", Expiry: now.Add(2 * time.Hour)}, now.Add(time.Hour), true); err != nil {
		t.Fatal(err)
	}
	e, tok, ok, err := s.Get("tickets", alice)
	if err != nil || !ok || tok.AccessToken != "at-a2" || tok.RefreshToken != "rt-a" || !e.Since.Equal(now) || e.Scope != "read" || !e.Refreshable {
		t.Fatalf("after refresh: %+v %+v %v %v", e, tok, ok, err)
	}

	// The file holds no token in the clear, and the key is 0600.
	data, _ := os.ReadFile(filepath.Join(dir, "tokens.json"))
	for _, secret := range []string{"at-a", "rt-a", "at-b"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("tokens.json shows %s", secret)
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, "tokens.key")); err != nil || fi.Mode().Perm() != 0o600 || fi.Size() != 32 {
		t.Errorf("key: %v %v", fi, err)
	}

	// Reopened, with the same key.
	s2, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, tok, ok, _ := s2.Get("tickets", bob); !ok || tok.AccessToken != "at-b" {
		t.Errorf("reopened: %+v", tok)
	}
	if l := s2.List(); len(l) != 2 || l[0].Server != "tickets" {
		t.Errorf("list: %+v", l)
	}

	// An entry moved to another principal does not decrypt.
	s2.mu.Lock()
	s2.entries[1].Principal = alice
	s2.entries[0].Principal = bob
	s2.mu.Unlock()
	if _, _, _, err := s2.Get("tickets", bob); err == nil {
		t.Error("swapped entry decrypted")
	}

	if _, ok, err := s.Delete("tickets", alice); !ok || err != nil {
		t.Errorf("delete: %v %v", ok, err)
	}
	if _, _, ok, _ := s.Get("tickets", alice); ok {
		t.Error("deleted entry still there")
	}

	if err := s.PutClient("tickets", "https://as", oauth.Client{ClientID: "dyn"}); err != nil {
		t.Fatal(err)
	}
	if c, ok := s.Client("tickets", "https://as"); !ok || c.ClientID != "dyn" {
		t.Errorf("client: %+v", c)
	}
	if _, ok := s.Client("tickets", "https://other"); ok {
		t.Error("client of another issuer")
	}

	// A short key is refused.
	bad := t.TempDir()
	_ = os.WriteFile(filepath.Join(bad, "tokens.key"), []byte("short"), 0o600)
	if _, err := OpenStore(bad); err == nil {
		t.Error("short key accepted")
	}
}
