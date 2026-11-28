package store

import (
	"context"
	"sync"
	"testing"
	"time"
)

func runShared(t *testing.T, c Collection, replica string) (*Shared, map[string][]byte) {
	t.Helper()
	s := &Shared{C: c, Replica: replica, MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond}
	own, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return s, own
}

func flushShared(t *testing.T, s *Shared) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
}

// Two writers keep their records side by side: each saves its own map
// without deleting the other's, and sees the other's.
func TestSharedWriters(t *testing.T) {
	c, _ := testCollection(t)
	a, _ := runShared(t, c, "gw-a")
	b, _ := runShared(t, c, "gw-b")
	a.Save(map[string][]byte{"p-1": []byte("a1")})
	b.Save(map[string][]byte{"p-2": []byte("b2"), "p-3": []byte("b3")})
	flushShared(t, a)
	flushShared(t, b)
	a.Save(map[string][]byte{"p-1": []byte("a1'")})
	flushShared(t, a)
	waitFor(t, "b's records at a", func() bool { o, _ := a.Others(); return len(o) == 2 && string(o["p-2"].Data) == "b2" })
	waitFor(t, "a's at b", func() bool { o, _ := b.Others(); return len(o) == 1 && string(o["p-1"].Data) == "a1'" })
	if got := listed(t, c); len(got) != 3 {
		t.Fatalf("records %v", got)
	}
	// A writer started again under its name loads its own records only.
	_, own := runShared(t, c, "gw-b")
	if len(own) != 2 || string(own["p-3"]) != "b3" {
		t.Fatalf("b's own %v", own)
	}
}

// The records of a writer that is gone are adopted by one live writer.
func TestSharedAdopt(t *testing.T) {
	c, _ := testCollection(t)
	gone, _ := runShared(t, c, "gw-gone")
	gone.Save(map[string][]byte{"p-1": []byte("x"), "p-2": []byte("y")})
	flushShared(t, gone)
	a, _ := runShared(t, c, "gw-a")
	b, _ := runShared(t, c, "gw-b")
	for _, s := range []*Shared{a, b} {
		waitFor(t, "the gone writer's records", func() bool { o, _ := s.Others(); return len(o) == 2 })
	}
	live := func(r string) bool { return r != "gw-gone" }
	got := make([]map[string][]byte, 2)
	var wg sync.WaitGroup
	for i, s := range []*Shared{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], _ = s.Adopt(context.Background(), live)
		}()
	}
	wg.Wait()
	if n := len(got[0]) + len(got[1]); n != 2 {
		t.Fatalf("adopted %v and %v", got[0], got[1])
	}
	names := listed(t, c)
	if len(names) != 2 {
		t.Fatalf("records after adoption %v", names)
	}
	for name := range names {
		if name[:len("gw-gone/")] == "gw-gone/" {
			t.Errorf("left %s", name)
		}
	}
	// The adopter's table owns them: saving without one deletes it.
	for i, s := range []*Shared{a, b} {
		if len(got[i]) == 0 {
			continue
		}
		s.Save(map[string][]byte{})
		flushShared(t, s)
	}
	if names := listed(t, c); len(names) != 0 {
		t.Fatalf("records after the adopters dropped them %v", names)
	}
}

// Records of one writer, before there were several (named by their id
// alone), are adopted as a gone writer's.
func TestSharedAdoptSingle(t *testing.T) {
	c, _ := testCollection(t)
	if _, err := c.Create(context.Background(), "p-old", []byte("o")); err != nil {
		t.Fatal(err)
	}
	a, _ := runShared(t, c, "gw-a")
	got, err := a.Adopt(context.Background(), func(string) bool { return true })
	if err != nil || string(got["p-old"]) != "o" {
		t.Fatalf("adopted %v %v", got, err)
	}
	if names := listed(t, c); len(names) != 1 || names["gw-a/p-old"] != "o" {
		t.Fatalf("records %v", names)
	}
}
