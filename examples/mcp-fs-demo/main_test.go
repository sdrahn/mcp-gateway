package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Symbolic links inside the root that point out of it are refused, as
// are paths that leave the root by name; files inside work.
func TestStaysInsideRoot(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, rootFS = t.TempDir(), nil // opened on first use
	defer func() { _ = rootFS.Close(); rootFS = nil }()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "filelink")); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ tool, path string }{
		{"read_file", "link/secret"},
		{"read_file", "filelink"},
		{"read_file", filepath.Join(root, "link", "secret")},
		{"write_file", "link/new"},
		{"list_dir", "link"},
		{"read_file", "../" + filepath.Base(outside) + "/secret"},
		{"read_file", filepath.Join(outside, "secret")},
	} {
		text, err := call(tc.tool, map[string]string{"path": tc.path, "content": "x"})
		if err == nil {
			t.Errorf("%s %s: no error (%q)", tc.tool, tc.path, text)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "new")); err == nil {
		t.Error("write_file through the link created a file outside the root")
	}

	if _, err := call("write_file", map[string]string{"path": "notes.txt", "content": "inside"}); err != nil {
		t.Fatal(err)
	}
	if text, err := call("read_file", map[string]string{"path": filepath.Join(root, "notes.txt")}); err != nil || text != "inside" {
		t.Fatalf("read_file: %q %v", text, err)
	}
	if text, err := call("list_dir", map[string]string{"path": "."}); err != nil || !strings.Contains(text, "notes.txt") {
		t.Fatalf("list_dir: %q %v", text, err)
	}
	if _, err := call("delete_file", map[string]string{"path": "notes.txt"}); err != nil {
		t.Fatal(err)
	}
}
