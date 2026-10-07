package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// outline_file lists ATX headings with their lines and section extents;
// headings in fenced code, #tags and setext underlines are not headings.
func TestOutlineFile(t *testing.T) {
	s, root := newTestServer(t, 1)
	doc := "# Title\n" + // 1
		"intro\n" + // 2
		"## One ##\n" + // 3
		"```sh\n" + // 4
		"# not a heading\n" + // 5
		"~~~\n" + // 6 (inside the backtick fence)
		"```\n" + // 7
		"#tag is not one\n" + // 8
		"   ### Deep\n" + // 9
		"text\n" + // 10
		"## Two\n" + // 11
		"Setext\n" + // 12
		"------\n" + // 13
		"    # indented code\n" + // 14
		"~~~~\n" + // 15
		"## in tildes\n" + // 16
		"~~~~\n" + // 17
		"end" // 18, no newline
	write(t, filepath.Join(root, "doc.md"), doc)

	r := call(t, s, "outline_file", map[string]any{"path": "doc.md"})
	got := mustOK(t, r)
	want := filepath.Join(root, "doc.md") + ": 18 lines, 154 B\n" +
		" 1  # Title  [18 lines, 154 B]\n" +
		" 3  ## One  [8 lines, 73 B]\n" +
		" 9  ### Deep  [2 lines, 17 B]\n" +
		"11  ## Two  [8 lines, 67 B]\n" +
		"(read a section: read_text_file with offset = its line, limit = its lines)"
	if got != want {
		t.Errorf("outline:\n%s\nwant:\n%s", got, want)
	}
	if len(doc) != 154 {
		t.Fatalf("test document is %d bytes", len(doc))
	}
	hs := r.Structured["headings"].([]any)
	if len(hs) != 4 || r.Structured["lines"].(float64) != 18 {
		t.Fatalf("structured: %v", r.Structured)
	}
	if h := hs[1].(map[string]any); h["title"] != "One" || h["level"].(float64) != 2 || h["line"].(float64) != 3 || h["lines"].(float64) != 8 {
		t.Errorf("structured heading: %v", h)
	}

	// The section's lines are what read_text_file reads with them.
	sec := mustOK(t, call(t, s, "read_text_file", map[string]any{"path": "doc.md", "offset": 11, "limit": 8}))
	if !strings.HasPrefix(sec, "## Two\n") || !strings.HasSuffix(sec, "end\n[lines 11-18 of 18]") {
		t.Errorf("section read: %q", sec)
	}

	// maxLevel leaves out deeper headings; their lines stay in the parent.
	got = mustOK(t, call(t, s, "outline_file", map[string]any{"path": "doc.md", "maxLevel": 2}))
	if strings.Contains(got, "Deep") || !strings.Contains(got, "## One  [8 lines") {
		t.Errorf("maxLevel 2: %s", got)
	}
	mustFail(t, call(t, s, "outline_file", map[string]any{"path": "doc.md", "maxLevel": 7}), "maxLevel")
}

// Files without headings, directories, binary files, and nothing outside
// the roots.
func TestOutlineFileEdges(t *testing.T) {
	s, root := newTestServer(t, 1)
	write(t, filepath.Join(root, "plain.txt"), "no headings\n#here\n")
	write(t, filepath.Join(root, "bin.dat"), "# x\x00\x01")
	outside := t.TempDir()
	write(t, filepath.Join(outside, "secret.md"), "# secret\n")
	if err := os.Symlink(filepath.Join(outside, "secret.md"), filepath.Join(root, "link.md")); err != nil {
		t.Fatal(err)
	}

	r := call(t, s, "outline_file", map[string]any{"path": "plain.txt"})
	if got := mustOK(t, r); !strings.HasSuffix(got, ": 2 lines, 18 B\nno Markdown headings: read it with read_text_file (head, or offset and limit)") {
		t.Errorf("no headings: %q", got)
	}
	if hs := r.Structured["headings"].([]any); len(hs) != 0 {
		t.Errorf("headings: %v", hs)
	}
	mustFail(t, call(t, s, "outline_file", map[string]any{"path": "."}), "is a directory")
	mustFail(t, call(t, s, "outline_file", map[string]any{"path": "bin.dat"}), "not a text file")
	mustFail(t, call(t, s, "outline_file", map[string]any{"path": "link.md"}), "")
	mustFail(t, call(t, s, "outline_file", map[string]any{"path": "../"}), "")
}
