package pep

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/principal"
)

func fakeOPA(t *testing.T, h http.HandlerFunc) *OPA {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "opa.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	return NewOPA(sock, 200*time.Millisecond)
}

func TestOPADecide(t *testing.T) {
	var gotInput Input
	o := fakeOPA(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DecisionPath {
			http.NotFound(w, r)
			return
		}
		var body struct{ Input Input }
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotInput = body.Input
		_, _ = w.Write([]byte(`{"result":{"effect":"ask","ask":{"channel":"form","prompt":"ok?"}}}`))
	})
	d, err := o.Decide(context.Background(), Input{Action: "tools.call", Resource: Resource{Server: "fs", Name: "write_file"}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Effect != Ask || d.Ask.Channel != ChannelForm || gotInput.Resource.Name != "write_file" {
		t.Fatalf("decision %+v, input %+v", d, gotInput)
	}
}

func TestOPAUndefinedIsError(t *testing.T) {
	o := fakeOPA(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) })
	if _, err := o.Decide(context.Background(), Input{}); err == nil {
		t.Fatal("expected error")
	}
	if got := Evaluate(context.Background(), o, Input{}); got.Effect != Deny {
		t.Fatalf("Evaluate = %+v", got)
	}
}

func TestOPATimeout(t *testing.T) {
	o := fakeOPA(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(time.Second)
		_, _ = w.Write([]byte(`{"result":{"effect":"allow"}}`))
	})
	if got := Evaluate(context.Background(), o, Input{}); got.Effect != Deny {
		t.Fatalf("Evaluate = %+v", got)
	}
}

func TestOPAUnreachable(t *testing.T) {
	o := NewOPA(filepath.Join(t.TempDir(), "missing.sock"), 100*time.Millisecond)
	if got := Evaluate(context.Background(), o, Input{}); got.Effect != Deny {
		t.Fatalf("Evaluate = %+v", got)
	}
}

func TestOPAVisible(t *testing.T) {
	o := fakeOPA(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != VisiblePath {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"result":[{"server":"fs","kind":"tool","name":"read_file"}]}`))
	})
	got, err := o.Visible(context.Background(), principal.Principal{Sub: "alice"}, []Resource{
		{Server: "fs", Kind: "tool", Name: "read_file"},
		{Server: "fs", Kind: "tool", Name: "delete_file"},
	})
	if err != nil || len(got) != 1 || got[0].Name != "read_file" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestOPAFingerprint(t *testing.T) {
	var rbac, other, profiles atomicString
	var ids atomic.Int64
	rbac.Store(`{"result":{"roles":{}}}`)
	profiles.Store(`{}`) // undefined: no setup packages
	other.Store(module("team.rego", "team", "v1"))
	o := fakeOPA(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/policies":
			_, _ = w.Write([]byte(`{"result":[` + module("authz.rego", "mcp", "authz") + `,` + other.Load() + `]}`))
		case "/v1/data/mcp/rbac":
			// With decision logging on (as mcp-opa.service runs OPA), every
			// response carries a new decision id.
			id := ids.Add(1)
			_, _ = w.Write([]byte(strings.Replace(rbac.Load(), "{", fmt.Sprintf(`{"decision_id":"%d",`, id), 1)))
		case "/v1/data/mcp/profiles":
			_, _ = w.Write([]byte(profiles.Load()))
		default:
			http.NotFound(w, r)
		}
	})
	a, err := o.Fingerprint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := o.Fingerprint(context.Background()); b != a {
		t.Fatal("fingerprint not stable")
	}
	// Another team's policy in the same OPA does not count.
	other.Store(module("team.rego", "team", "v2"))
	if b, _ := o.Fingerprint(context.Background()); b != a {
		t.Fatal("fingerprint changed with a policy outside mcp")
	}
	rbac.Store(`{"result":{"roles":{"x":{}}}}`)
	c, _ := o.Fingerprint(context.Background())
	if c == a {
		t.Fatal("fingerprint did not change with the data")
	}
	// A setup package installed: its roles count.
	profiles.Store(`{"result":{"systemd":{"roles":{"systemd-reader":{}}}}}`)
	if d, _ := o.Fingerprint(context.Background()); d == c || d == "" {
		t.Fatal("fingerprint did not change with shipped roles")
	}
}

// module is a /v1/policies entry for package data.<root>.<name>.
func module(id, root, name string) string {
	return fmt.Sprintf(`{"id":%q,"raw":"package %s.%s","ast":{"package":{"path":[`+
		`{"type":"var","value":"data"},{"type":"string","value":%q},{"type":"string","value":%q}]}}}`,
		id, root, name, root, name)
}

type atomicString struct {
	mu sync.Mutex
	s  string
}

func (a *atomicString) Store(s string) { a.mu.Lock(); a.s = s; a.mu.Unlock() }
func (a *atomicString) Load() string   { a.mu.Lock(); defer a.mu.Unlock(); return a.s }

func TestOPABundles(t *testing.T) {
	o := fakeOPA(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/data/system/bundles" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"result":{"mcp":{"etag":"","manifest":{"revision":"r42","roots":[""]}}}}`))
	})
	got, err := o.Bundles(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["mcp"] != "r42" {
		t.Fatalf("got %v", got)
	}
}
