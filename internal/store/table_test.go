package store

import (
	"context"
	"testing"
	"time"
)

func runTable(t *testing.T, c Collection) *Table {
	t.Helper()
	tb := &Table{C: c, MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond}
	if _, err := tb.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tb.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return tb
}

func flush(t *testing.T, tb *Table) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tb.Flush(ctx); err != nil {
		t.Fatal(err)
	}
}

func listed(t *testing.T, c Collection) map[string]string {
	t.Helper()
	recs, _, err := c.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range recs {
		out[r.Name] = string(r.Data)
	}
	return out
}

// Saving the whole map writes what changed: new records, changed ones,
// and deletes what is gone.
func TestTableWrites(t *testing.T) {
	c, api := testCollection(t)
	tb := runTable(t, c)
	tb.Save(map[string][]byte{"a": []byte("1"), "b": []byte("2")})
	flush(t, tb)
	if got := listed(t, c); len(got) != 2 || got["a"] != "1" || got["b"] != "2" {
		t.Fatalf("after the first save: %v", got)
	}
	puts := api.Requests("PUT") + api.Requests("POST")
	tb.Save(map[string][]byte{"a": []byte("1"), "c": []byte("3")})
	flush(t, tb)
	if got := listed(t, c); len(got) != 2 || got["a"] != "1" || got["c"] != "3" {
		t.Fatalf("after the second save: %v", got)
	}
	if n := api.Requests("PUT") + api.Requests("POST") - puts; n != 1 {
		t.Errorf("%d writes for one new record, want 1 (a did not change)", n)
	}
	tb.Save(map[string][]byte{"a": []byte("9")})
	flush(t, tb)
	if got := listed(t, c); len(got) != 1 || got["a"] != "9" {
		t.Fatalf("after the third save: %v", got)
	}
	// Loaded again (a restart): the records as written.
	tb2 := &Table{C: c}
	got, err := tb2.Load(context.Background())
	if err != nil || len(got) != 1 || string(got["a"]) != "9" {
		t.Fatalf("loaded: %v %v", got, err)
	}
}

// A record changed under the writer (another writer's) is listed again
// and written.
func TestTableStale(t *testing.T) {
	c, _ := testCollection(t)
	tb := runTable(t, c)
	tb.Save(map[string][]byte{"a": []byte("1")})
	flush(t, tb)
	other, _ := NewKubernetes(c.Client, "gw", "grants")
	recs, _, _ := other.List(context.Background())
	if _, err := other.Update(context.Background(), Record{Name: "a", Data: []byte("x"), Version: recs[0].Version}); err != nil {
		t.Fatal(err)
	}
	_, _ = other.Create(context.Background(), "b", []byte("y"))
	tb.Save(map[string][]byte{"a": []byte("2"), "b": []byte("3")})
	flush(t, tb)
	if got := listed(t, c); got["a"] != "2" || got["b"] != "3" {
		t.Fatalf("after writes under the writer: %v", got)
	}
}

// Errors are retried; only the latest map is written.
func TestTableRetries(t *testing.T) {
	c, api := testCollection(t)
	f := &failingWrites{Kubernetes: c}
	f.fail.Store(true)
	tb := runTable(t, f)
	tb.Save(map[string][]byte{"a": []byte("1")})
	tb.Save(map[string][]byte{"a": []byte("2")})
	time.Sleep(50 * time.Millisecond)
	if n := api.Len("gw"); n != 0 {
		t.Fatalf("%d records while failing", n)
	}
	f.fail.Store(false)
	flush(t, tb)
	if got := listed(t, c); got["a"] != "2" {
		t.Fatalf("after the store came back: %v", got)
	}
}

// A key is made once: later uses, and other writers, get the same.
func TestKey(t *testing.T) {
	c, _ := testCollection(t)
	ctx := context.Background()
	k1, err := Key(ctx, c, "audit", 32)
	if err != nil || len(k1) != 32 {
		t.Fatalf("made: %v %d", err, len(k1))
	}
	other, _ := NewKubernetes(c.Client, "gw", "grants")
	k2, err := Key(ctx, other, "audit", 32)
	if err != nil || string(k2) != string(k1) {
		t.Fatalf("again: %v", err)
	}
	if k3, _ := Key(ctx, c, "tokens", 32); string(k3) == string(k1) {
		t.Fatal("two keys alike")
	}
	if _, err := Key(ctx, c, "audit", 16); err == nil {
		t.Fatal("a key of another size accepted")
	}
}
