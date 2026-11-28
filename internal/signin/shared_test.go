package signin

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/kube"
	"github.com/sdrahn/mcp-gateway/internal/kube/kubetest"
	"github.com/sdrahn/mcp-gateway/internal/oauth"
	"github.com/sdrahn/mcp-gateway/internal/store"
)

func openShared(t *testing.T, api *kubetest.Secrets) *Store {
	t.Helper()
	coll := func(name string) store.Collection {
		c, err := store.NewKubernetes(api.Client(), "gw", name)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s, err := OpenSharedStore(ctx, coll("tokens"), coll("keys"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// With a shared store, the tokens are records, sealed under a key that is
// a record too: a gateway started again (another store on the same API)
// reads them; nothing in the API holds a token in the clear.
func TestSharedStore(t *testing.T) {
	api := kubetest.NewSecrets(t)
	s := openShared(t, api)
	alice := Key{Transport: "http", Issuer: "https://idp", Sub: "alice"}
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	if err := s.Put("tickets", "https://t.example/mcp", alice, &oauth.Token{AccessToken: "at-a", RefreshToken: "rt-a", Expiry: now.Add(time.Hour)}, now, false); err != nil {
		t.Fatal(err)
	}
	if err := s.PutClient("tickets", "https://as", oauth.Client{ClientID: "dyn"}); err != nil {
		t.Fatal(err)
	}
	// Written when Put returns: key, token, client.
	if n := api.Len("gw"); n != 3 {
		t.Fatalf("%d records", n)
	}
	c, _ := store.NewKubernetes(api.Client(), "gw", "tokens")
	recs, _, _ := c.List(context.Background())
	for _, r := range recs {
		for _, secret := range []string{"at-a", "rt-a", "dyn"} {
			if strings.Contains(string(r.Data), secret) {
				t.Errorf("record %s shows %s", r.Name, secret)
			}
		}
	}

	s2 := openShared(t, api)
	if _, tok, ok, err := s2.Get("tickets", alice); err != nil || !ok || tok.RefreshToken != "rt-a" {
		t.Fatalf("restarted: %+v %v %v", tok, ok, err)
	}
	if cl, ok := s2.Client("tickets", "https://as"); !ok || cl.ClientID != "dyn" {
		t.Fatalf("client after restart: %+v", cl)
	}
	if _, ok, err := s2.Delete("tickets", alice); !ok || err != nil {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if n := api.Len("gw"); n != 2 {
		t.Fatalf("%d records after the delete", n)
	}
	s3 := openShared(t, api)
	if _, _, ok, _ := s3.Get("tickets", alice); ok {
		t.Fatal("deleted sign-in back after a restart")
	}
}

// A key in the store of another size is refused, as a short tokens.key.
func TestSharedStoreBadKey(t *testing.T) {
	api := kubetest.NewSecrets(t)
	keys, _ := store.NewKubernetes(api.Client(), "gw", "keys")
	tokens, _ := store.NewKubernetes(api.Client(), "gw", "tokens")
	api.Put("gw", kube.Secret{Metadata: kube.ObjectMeta{Name: keys.SecretName("tokens"),
		Labels:      map[string]string{store.ManagedByLabel: store.ManagedBy, store.CollectionLabel: "keys"},
		Annotations: map[string]string{store.NameAnnotation: "tokens"}},
		Data: map[string][]byte{"record": []byte("short")}})
	if _, err := OpenSharedStore(context.Background(), tokens, keys, slog.Default()); err == nil {
		t.Fatal("short key accepted")
	}
}
