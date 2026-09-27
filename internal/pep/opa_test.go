package pep

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"sync"
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
	var rbac atomicString
	rbac.Store(`{"result":{"roles":{}}}`)
	o := fakeOPA(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/policies":
			_, _ = w.Write([]byte(`{"result":[{"id":"authz.rego","raw":"package mcp.authz"}]}`))
		case "/v1/data/rbac":
			_, _ = w.Write([]byte(rbac.Load()))
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
	rbac.Store(`{"result":{"roles":{"x":{}}}}`)
	if c, _ := o.Fingerprint(context.Background()); c == a {
		t.Fatal("fingerprint did not change with the data")
	}
}

type atomicString struct {
	mu sync.Mutex
	s  string
}

func (a *atomicString) Store(s string) { a.mu.Lock(); a.s = s; a.mu.Unlock() }
func (a *atomicString) Load() string   { a.mu.Lock(); defer a.mu.Unlock(); return a.s }
