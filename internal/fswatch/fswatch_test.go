package fswatch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func expect(t *testing.T, w *Watcher, what string) {
	t.Helper()
	select {
	case <-w.Events():
	case <-time.After(5 * time.Second):
		t.Fatalf("no event: %s", what)
	}
}

func quiet(t *testing.T, w *Watcher, what string) {
	t.Helper()
	select {
	case <-w.Events():
		t.Fatalf("unexpected event: %s", what)
	case <-time.After(100 * time.Millisecond):
	}
}

func drain(w *Watcher) {
	time.Sleep(50 * time.Millisecond)
	select {
	case <-w.Events():
	default:
	}
}

func TestWatcher(t *testing.T) {
	w, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	dir, other := t.TempDir(), t.TempDir()
	missing := filepath.Join(dir, "missing")
	failed := w.Set([]string{dir, missing})
	if len(failed) != 1 || failed[missing] == nil {
		t.Fatalf("failed %v", failed)
	}

	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	expect(t, w, "write")
	drain(w)

	// Replaced by rename, as editors and certbot do.
	tmp := filepath.Join(other, "a.yaml")
	if err := os.WriteFile(tmp, []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	quiet(t, w, "write outside the watched directories")
	if err := os.Rename(tmp, filepath.Join(dir, "a.yaml")); err != nil {
		t.Fatal(err)
	}
	expect(t, w, "rename")
	drain(w)

	// A directory that appears is watched once Set is called again; one
	// no longer listed is not.
	if err := os.Mkdir(missing, 0o755); err != nil {
		t.Fatal(err)
	}
	drain(w)
	if failed := w.Set([]string{missing}); len(failed) != 0 {
		t.Fatalf("failed %v", failed)
	}
	drain(w) // dropping a watch is an event (IN_IGNORED): harmless
	if err := os.WriteFile(filepath.Join(dir, "b.yaml"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	quiet(t, w, "write in a directory no longer watched")
	if err := os.Remove(filepath.Join(missing)); err != nil {
		t.Fatal(err)
	}
	expect(t, w, "watched directory removed")
}

func TestNil(t *testing.T) {
	var w *Watcher
	if w.Events() != nil || w.Close() != nil {
		t.Fatal("nil watcher")
	}
}
