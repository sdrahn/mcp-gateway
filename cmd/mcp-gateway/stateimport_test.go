package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/kube/kubetest"
	"github.com/sdrahn/mcp-gateway/internal/oauth"
	"github.com/sdrahn/mcp-gateway/internal/signin"
	"github.com/sdrahn/mcp-gateway/internal/store"
)

// The files of a volume go into the store at its first start, once: the
// records named as the gateway names them, the sign-in tokens readable
// under the imported key, the audit key the same.
func TestImportState(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	write("grants.json", `[{"id":"g-1","sub":"alice","server":"fs","tool":"read","scope":"duration","expires":"`+exp+`","approved_by":"root","channel":"oob"}]`)
	write("pending.json", `[{"id":"p-1","prompt":"Write?"},{"id":"p-2","prompt":"Read?"}]`)
	write("clients.json", `[{"id":"s-1","kind":"session","sub":"alice"}]`)
	auditKey := []byte("0123456789abcdef0123456789abcdef")
	write("audit.key", string(auditKey))
	tokDir := filepath.Join(dir, "tokens")
	_ = os.Mkdir(tokDir, 0o700)
	ts, err := signin.OpenStore(tokDir)
	if err != nil {
		t.Fatal(err)
	}
	alice := signin.Key{Transport: "http", Issuer: "https://idp", Sub: "alice"}
	if err := ts.Put("tickets", "https://t/mcp", alice, &oauth.Token{AccessToken: "at", RefreshToken: "rt"}, time.Now(), false); err != nil {
		t.Fatal(err)
	}

	api := kubetest.NewSecrets(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &sharedStore{ctx: ctx, cancel: cancel, client: api.Client(), namespace: "gw"}
	gw := &config.Gateway{StateDir: dir}
	if err := importState(ctx, slog.Default(), gw, s); err != nil {
		t.Fatal(err)
	}
	names := func(coll string) map[string]bool {
		c, _ := s.collection(coll)
		recs, _, err := c.List(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, r := range recs {
			out[r.Name] = true
		}
		return out
	}
	if g := names("grants"); !g["g-1"] || len(g) != 1 {
		t.Errorf("grants %v", g)
	}
	if p := names("pending"); !p["p-1"] || !p["p-2"] || len(p) != 2 {
		t.Errorf("pending %v", p)
	}
	if c := names("clients"); !c["s-1"] {
		t.Errorf("clients %v", c)
	}
	keys, _ := s.collection("keys")
	if k, err := store.Key(ctx, keys, "audit", 32); err != nil || string(k) != string(auditKey) {
		t.Errorf("audit key %q %v", k, err)
	}
	tokens, _ := s.collection("tokens")
	shared, err := signin.OpenSharedStore(ctx, tokens, keys, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if _, tok, ok, err := shared.Get("tickets", alice); err != nil || !ok || tok.RefreshToken != "rt" {
		t.Fatalf("imported token: %+v %v %v", tok, ok, err)
	}

	// Once: a file changed since is not read again.
	n := api.Len("gw")
	write("pending.json", `[{"id":"p-3","prompt":"Again?"}]`)
	if err := importState(ctx, slog.Default(), gw, s); err != nil {
		t.Fatal(err)
	}
	if api.Len("gw") != n || names("pending")["p-3"] {
		t.Error("imported twice")
	}
}

// The doctor in the gateway lists the shared store's keys: ok when the
// API server answers, fail when it does not.
func TestSelfCheckSharedStore(t *testing.T) {
	api := kubetest.NewSecrets(t)
	keys, _ := store.NewKubernetes(api.Client(), "gw", "keys")
	gw := &config.Gateway{Replication: config.Replication{Store: "kubernetes", Namespace: "gw"}}
	c := &selfCheck{gw: gw, shared: keys}
	if r := c.sharedStore(context.Background()); r.Status != "ok" || r.Check != "shared store" {
		t.Fatalf("reachable: %+v", r)
	}
	down, _ := store.NewKubernetes(api.Client(), "gw", "keys")
	down.Client.Server = "http://127.0.0.1:1"
	c.shared = down
	if r := c.sharedStore(context.Background()); r.Status != "fail" {
		t.Fatalf("unreachable: %+v", r)
	}
}
