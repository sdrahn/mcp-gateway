package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A file written anywhere in the policy trees, also in a directory
// created after the start, is told on the channel.
func TestWatchPolicyFiles(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "policy", "rbac", "data.json")
	shipped := filepath.Join(root, "shipped")
	for _, d := range []string{filepath.Dir(data), shipped} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changed := watchPolicyFiles(ctx, slog.New(slog.DiscardHandler), data, shipped)
	if changed == nil {
		t.Skip("no inotify")
	}
	expect := func(what string) {
		t.Helper()
		select {
		case <-changed:
		case <-time.After(5 * time.Second):
			t.Fatalf("not told: %s", what)
		}
		time.Sleep(50 * time.Millisecond)
		select { // drain what the same change caused
		case <-changed:
		default:
		}
	}
	write := func(path string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(data)
	expect("role data")
	write(filepath.Join(root, "policy", "custom.rego"))
	expect("a rule next to the role data")
	if err := os.MkdirAll(filepath.Join(shipped, "mcp", "profiles"), 0o755); err != nil {
		t.Fatal(err)
	}
	expect("a new directory")
	time.Sleep(100 * time.Millisecond)
	write(filepath.Join(shipped, "mcp", "profiles", "data.json"))
	expect("a file in the new directory")
}
