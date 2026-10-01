package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplaced(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "mcp-gateway")
	if err := os.WriteFile(exe, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	stat := func() os.FileInfo {
		fi, err := os.Stat(exe)
		if err != nil {
			return nil
		}
		return fi
	}
	start := stat()
	if replaced(start, stat()) {
		t.Fatal("unchanged file reported as replaced")
	}
	// An update writes a new file and renames it over the old one, as rpm does.
	if err := os.WriteFile(exe+".new", []byte("v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(exe+".new", exe); err != nil {
		t.Fatal(err)
	}
	if !replaced(start, stat()) {
		t.Fatal("replaced file not noticed")
	}
	if !replaced(start, nil) {
		t.Fatal("removed file not noticed")
	}
	if replaced(nil, stat()) {
		t.Fatal("unknown start reported as replaced")
	}
}
