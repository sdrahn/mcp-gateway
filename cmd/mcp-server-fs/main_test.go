package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// newTestServer returns a server on fresh directories (the first is
// returned too).
func newTestServer(t *testing.T, n int) (*fileServer, string) {
	t.Helper()
	s := &fileServer{maxRead: 1 << 20, maxWrite: 1 << 20, maxEntries: 1000}
	for i := 0; i < n; i++ {
		s.dirs = append(s.dirs, &allowed{path: t.TempDir()})
	}
	return s, s.dirs[0].path
}

type callResult struct {
	Content []struct {
		Type     string         `json:"type"`
		Text     string         `json:"text"`
		Data     string         `json:"data"`
		MimeType string         `json:"mimeType"`
		Resource map[string]any `json:"resource"`
	} `json:"content"`
	IsError    bool           `json:"isError"`
	Structured map[string]any `json:"structuredContent"`
}

func (r callResult) text() string {
	var b strings.Builder
	for _, c := range r.Content {
		b.WriteString(c.Text)
	}
	return b.String()
}

// call runs a tool and returns its result; protocol errors fail the test.
func call(t *testing.T, s *fileServer, name string, args any) callResult {
	t.Helper()
	raw, _ := json.Marshal(args)
	res, err := s.call(context.Background(), name, raw)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	b, _ := json.Marshal(res)
	var r callResult
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func mustOK(t *testing.T, r callResult) string {
	t.Helper()
	if r.IsError {
		t.Fatalf("tool error: %s", r.text())
	}
	return r.text()
}

func mustFail(t *testing.T, r callResult, want string) {
	t.Helper()
	if !r.IsError || !strings.Contains(r.text(), want) {
		t.Fatalf("want a tool error with %q, got isError=%v %q", want, r.IsError, r.text())
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Symbolic links inside a root that point out of it are refused, as are
// paths that leave the roots by name; nothing is created outside.
func TestStaysInsideRoots(t *testing.T) {
	s, root := newTestServer(t, 1)
	outside := t.TempDir()
	write(t, filepath.Join(outside, "secret"), "outside")
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "filelink")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"read_text_file", map[string]any{"path": "link/secret"}, "outside the allowed directories"},
		{"read_text_file", map[string]any{"path": "filelink"}, "outside the allowed directories"},
		{"read_file", map[string]any{"path": filepath.Join(root, "link", "secret")}, "outside the allowed directories"},
		{"read_media_file", map[string]any{"path": "filelink"}, "outside the allowed directories"},
		{"write_file", map[string]any{"path": "link/new", "content": "x"}, "outside the allowed directories"},
		{"create_directory", map[string]any{"path": "link/newdir"}, "outside the allowed directories"},
		{"list_directory", map[string]any{"path": "link"}, "outside the allowed directories"},
		{"directory_tree", map[string]any{"path": "link"}, "outside the allowed directories"},
		{"read_text_file", map[string]any{"path": "../" + filepath.Base(outside) + "/secret"}, "outside the allowed directories"},
		{"read_text_file", map[string]any{"path": filepath.Join(outside, "secret")}, "outside the allowed directories"},
		{"move_file", map[string]any{"source": "filelink", "destination": filepath.Join(outside, "moved")}, "outside the allowed directories"},
	} {
		mustFail(t, call(t, s, tc.tool, tc.args), tc.want)
	}
	for _, name := range []string{"new", "newdir", "moved"} {
		if _, err := os.Lstat(filepath.Join(outside, name)); err == nil {
			t.Errorf("%s was created outside the root", name)
		}
	}
	// The tree lists the links as links and does not follow them.
	tree := mustOK(t, call(t, s, "directory_tree", map[string]any{"path": "."}))
	if strings.Contains(tree, "secret") || !strings.Contains(tree, `"type": "symlink"`) {
		t.Errorf("tree followed a link out of the root: %s", tree)
	}
	// get_file_info on a link out of the root says so, without its target.
	info := call(t, s, "get_file_info", map[string]any{"path": "filelink"})
	if info.Structured["symlink"] != true || info.Structured["type"] != "symlink" {
		t.Errorf("get_file_info filelink: %+v", info.Structured)
	}
}

func TestPathResolution(t *testing.T) {
	s, first := newTestServer(t, 2)
	second := s.dirs[1].path
	write(t, filepath.Join(first, "a"), "first")
	write(t, filepath.Join(second, "a"), "second")
	if got := mustOK(t, call(t, s, "read_text_file", map[string]any{"path": "a"})); got != "first" {
		t.Errorf("relative path: %q", got)
	}
	if got := mustOK(t, call(t, s, "read_text_file", map[string]any{"path": filepath.Join(second, "a")})); got != "second" {
		t.Errorf("second root: %q", got)
	}
	dirs := call(t, s, "list_allowed_directories", map[string]any{})
	if got := dirs.Structured["directories"].([]any); len(got) != 2 || got[0] != first || got[1] != second {
		t.Errorf("allowed directories: %v", got)
	}
	// A nested root wins for paths below it.
	nested := filepath.Join(first, "nested")
	write(t, filepath.Join(nested, "f"), "nested")
	s.dirs = append(s.dirs, &allowed{path: nested})
	tg, err := s.resolve(filepath.Join(nested, "f"))
	if err != nil || tg.dir.path != nested || tg.rel != "f" {
		t.Errorf("nested root: %+v %v", tg, err)
	}
	mustFail(t, call(t, s, "read_text_file", map[string]any{"path": ""}), "path is required")
	mustFail(t, call(t, s, "read_text_file", map[string]any{"path": "a", "bogus": 1}), "invalid arguments")
}

func TestReadText(t *testing.T) {
	s, root := newTestServer(t, 1)
	write(t, filepath.Join(root, "lines"), "1\n2\n3\n4\n5\n")
	write(t, filepath.Join(root, "nonl"), "a\nb\nc")
	write(t, filepath.Join(root, "bin"), "\x00\x01\x02")
	for _, tc := range []struct {
		args map[string]any
		want string
	}{
		{map[string]any{"path": "lines"}, "1\n2\n3\n4\n5\n"},
		{map[string]any{"path": "lines", "head": 2}, "1\n2\n"},
		{map[string]any{"path": "lines", "tail": 2}, "4\n5\n"},
		{map[string]any{"path": "lines", "tail": 10}, "1\n2\n3\n4\n5\n"},
		{map[string]any{"path": "nonl", "tail": 2}, "b\nc"},
		{map[string]any{"path": "nonl", "head": 9}, "a\nb\nc"},
	} {
		if got := mustOK(t, call(t, s, "read_text_file", tc.args)); got != tc.want {
			t.Errorf("%v: %q, want %q", tc.args, got, tc.want)
		}
	}
	mustFail(t, call(t, s, "read_text_file", map[string]any{"path": "lines", "head": 1, "tail": 1}), "one of head, tail")
	mustFail(t, call(t, s, "read_text_file", map[string]any{"path": "bin"}), "read_media_file")
	mustFail(t, call(t, s, "read_text_file", map[string]any{"path": "."}), "is a directory")
	mustFail(t, call(t, s, "read_text_file", map[string]any{"path": "missing"}), "no such file")

	// Larger than the limit: refused whole, readable in parts.
	s.maxRead = 4
	mustFail(t, call(t, s, "read_text_file", map[string]any{"path": "lines"}), "head or tail")
	if got := mustOK(t, call(t, s, "read_text_file", map[string]any{"path": "lines", "tail": 1})); got != "5\n" {
		t.Errorf("tail under the limit: %q", got)
	}
	mustFail(t, call(t, s, "read_text_file", map[string]any{"path": "lines", "head": 5}), "exceed")
}

func TestTailLinesLarge(t *testing.T) {
	s, root := newTestServer(t, 1)
	var b strings.Builder
	for i := 0; i < 50000; i++ {
		b.WriteString("line\n")
	}
	b.WriteString("last\n")
	write(t, filepath.Join(root, "big"), b.String())
	if got := mustOK(t, call(t, s, "read_text_file", map[string]any{"path": "big", "tail": 2})); got != "line\nlast\n" {
		t.Errorf("tail across blocks: %q", got)
	}
}

func TestReadMediaAndMultiple(t *testing.T) {
	s, root := newTestServer(t, 1)
	png := "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
	write(t, filepath.Join(root, "img.png"), png)
	write(t, filepath.Join(root, "data.bin"), "\x00\xff")
	write(t, filepath.Join(root, "a.txt"), "A")
	write(t, filepath.Join(root, "b.txt"), "B")

	r := call(t, s, "read_media_file", map[string]any{"path": "img.png"})
	mustOK(t, r)
	if c := r.Content[0]; c.Type != "image" || c.MimeType != "image/png" || c.Data != base64.StdEncoding.EncodeToString([]byte(png)) {
		t.Errorf("image: %+v", c)
	}
	r = call(t, s, "read_media_file", map[string]any{"path": "data.bin"})
	if c := r.Content[0]; c.Type != "resource" || c.Resource["blob"] != base64.StdEncoding.EncodeToString([]byte("\x00\xff")) {
		t.Errorf("binary: %+v", c)
	}

	got := mustOK(t, call(t, s, "read_multiple_files", map[string]any{"paths": []string{"a.txt", "missing", "b.txt"}}))
	for _, want := range []string{filepath.Join(root, "a.txt") + ":\nA", "missing: error:", filepath.Join(root, "b.txt") + ":\nB"} {
		if !strings.Contains(got, want) {
			t.Errorf("read_multiple_files lacks %q: %q", want, got)
		}
	}
	// The read limit is shared by the files of one call.
	s.maxRead = 1
	got = mustOK(t, call(t, s, "read_multiple_files", map[string]any{"paths": []string{"a.txt", "b.txt"}}))
	if !strings.Contains(got, ":\nA") || strings.Contains(got, ":\nB") {
		t.Errorf("shared limit: %q", got)
	}
}

func TestListings(t *testing.T) {
	s, root := newTestServer(t, 1)
	write(t, filepath.Join(root, "b.txt"), "bb")
	write(t, filepath.Join(root, "a.txt"), "aaaa")
	write(t, filepath.Join(root, "dir", "x.go"), "package x")
	write(t, filepath.Join(root, "node_modules", "m.go"), "skip")
	if got := mustOK(t, call(t, s, "list_directory", map[string]any{"path": "."})); got != "[FILE] a.txt\n[FILE] b.txt\n[DIR] dir\n[DIR] node_modules" {
		t.Errorf("list_directory: %q", got)
	}
	if got := mustOK(t, call(t, s, "list_dir", map[string]any{"path": root})); got != "a.txt\nb.txt\ndir\nnode_modules" {
		t.Errorf("list_dir: %q", got)
	}
	got := mustOK(t, call(t, s, "list_directory_with_sizes", map[string]any{"path": ".", "sortBy": "size"}))
	if !strings.HasPrefix(got, "[FILE] a.txt") || !strings.Contains(got, "2 files, 2 directories, 6 B in files") {
		t.Errorf("list_directory_with_sizes: %q", got)
	}

	r := call(t, s, "search_files", map[string]any{"path": ".", "pattern": "*.go", "excludePatterns": []string{"node_modules"}})
	if got := r.Structured["matches"].([]any); len(got) != 1 || got[0] != filepath.Join(root, "dir", "x.go") {
		t.Errorf("search *.go: %v", got)
	}
	r = call(t, s, "search_files", map[string]any{"path": ".", "pattern": "**/*.go"})
	if got := r.Structured["matches"].([]any); len(got) != 2 {
		t.Errorf("search **/*.go: %v", got)
	}
	r = call(t, s, "search_files", map[string]any{"path": ".", "pattern": "dir/*.go"})
	if got := r.Structured["matches"].([]any); len(got) != 1 {
		t.Errorf("search dir/*.go: %v", got)
	}
	mustFail(t, call(t, s, "search_files", map[string]any{"path": ".", "pattern": "["}), "not a valid")

	var tree []map[string]any
	if err := json.Unmarshal([]byte(mustOK(t, call(t, s, "directory_tree",
		map[string]any{"path": ".", "excludePatterns": []string{"node_modules"}}))), &tree); err != nil {
		t.Fatal(err)
	}
	if len(tree) != 3 || tree[2]["name"] != "dir" || len(tree[2]["children"].([]any)) != 1 {
		t.Errorf("tree: %v", tree)
	}

	// Entry limits.
	s.maxEntries = 2
	if got := mustOK(t, call(t, s, "list_directory", map[string]any{"path": "."})); !strings.HasSuffix(got, "(only the first 2 entries)") {
		t.Errorf("limited listing: %q", got)
	}
	r = call(t, s, "search_files", map[string]any{"path": ".", "pattern": "*"})
	if r.Structured["truncated"] != true || len(r.Structured["matches"].([]any)) != 2 {
		t.Errorf("limited search: %v", r.Structured)
	}
}

func TestWalkCancelled(t *testing.T) {
	s, root := newTestServer(t, 1)
	write(t, filepath.Join(root, "a", "b"), "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tg, _ := s.resolve(".")
	if err := s.walk(ctx, tg, nil, func(string, os.DirEntry) bool { return true }); err == nil {
		t.Error("a cancelled walk went on")
	}
}

func TestWriteAtomicAndEdit(t *testing.T) {
	s, root := newTestServer(t, 1)
	p := filepath.Join(root, "f.txt")
	write(t, p, "one\ntwo\nthree\n")
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	mustOK(t, call(t, s, "write_file", map[string]any{"path": "f.txt", "content": "alpha\nbeta\n"}))
	if b, _ := os.ReadFile(p); string(b) != "alpha\nbeta\n" {
		t.Errorf("content: %q", b)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode not kept: %v", fi.Mode())
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 1 {
		t.Errorf("temporary file left: %v", entries)
	}
	mustFail(t, call(t, s, "write_file", map[string]any{"path": "nodir/f", "content": "x"}), "create_directory")
	mustFail(t, call(t, s, "write_file", map[string]any{"path": "f.txt"}), "content is required")
	s.maxWrite = 3
	mustFail(t, call(t, s, "write_file", map[string]any{"path": "f.txt", "content": "toolong"}), "may write")
	s.maxWrite = 1 << 20

	// edit_file: a diff, dry run first.
	edit := map[string]any{"path": "f.txt", "edits": []map[string]string{{"oldText": "beta", "newText": "gamma"}}, "dryRun": true}
	diff := mustOK(t, call(t, s, "edit_file", edit))
	if !strings.Contains(diff, "-beta\n+gamma\n") || !strings.HasPrefix(diff, "--- a/f.txt\n+++ b/f.txt\n@@ -1,2 +1,2 @@") {
		t.Errorf("diff: %q", diff)
	}
	if b, _ := os.ReadFile(p); string(b) != "alpha\nbeta\n" {
		t.Errorf("dry run changed the file: %q", b)
	}
	edit["dryRun"] = false
	mustOK(t, call(t, s, "edit_file", edit))
	if b, _ := os.ReadFile(p); string(b) != "alpha\ngamma\n" {
		t.Errorf("edited: %q", b)
	}
	mustFail(t, call(t, s, "edit_file", map[string]any{"path": "f.txt", "edits": []map[string]string{{"oldText": "zeta", "newText": "x"}}}), "not found")
	write(t, p, "x\nx\n")
	mustFail(t, call(t, s, "edit_file", map[string]any{"path": "f.txt", "edits": []map[string]string{{"oldText": "x", "newText": "y"}}}), "occurs 2 times")
	// CRLF files take edits written with \n.
	write(t, p, "a\r\nb\r\n")
	mustOK(t, call(t, s, "edit_file", map[string]any{"path": "f.txt", "edits": []map[string]string{{"oldText": "a\nb", "newText": "c\nd"}}}))
	if b, _ := os.ReadFile(p); string(b) != "c\r\nd\r\n" {
		t.Errorf("crlf: %q", b)
	}

	// Writing over a symbolic link is refused (it would replace the link).
	if err := os.Symlink("f.txt", filepath.Join(root, "ln")); err != nil {
		t.Fatal(err)
	}
	mustFail(t, call(t, s, "write_file", map[string]any{"path": "ln", "content": "x"}), "symbolic link")
}

func TestDirectoriesMoveDelete(t *testing.T) {
	s, root := newTestServer(t, 2)
	mustOK(t, call(t, s, "create_directory", map[string]any{"path": "a/b/c"}))
	mustOK(t, call(t, s, "create_directory", map[string]any{"path": "a/b/c"})) // idempotent
	write(t, filepath.Join(root, "file"), "f")
	mustFail(t, call(t, s, "create_directory", map[string]any{"path": "file/sub"}), "not a directory")

	mustOK(t, call(t, s, "move_file", map[string]any{"source": "file", "destination": "a/b/moved"}))
	if b, _ := os.ReadFile(filepath.Join(root, "a/b/moved")); string(b) != "f" {
		t.Errorf("moved: %q", b)
	}
	write(t, filepath.Join(root, "other"), "o")
	mustFail(t, call(t, s, "move_file", map[string]any{"source": "other", "destination": "a/b/moved"}), "already exists")
	mustFail(t, call(t, s, "move_file", map[string]any{"source": "missing", "destination": "x"}), "no such file")
	mustFail(t, call(t, s, "move_file", map[string]any{"source": "other", "destination": filepath.Join(s.dirs[1].path, "x")}), "different allowed directories")

	mustFail(t, call(t, s, "delete_file", map[string]any{"path": "a"}), "not empty")
	mustOK(t, call(t, s, "delete_file", map[string]any{"path": "other"}))
	mustFail(t, call(t, s, "delete_file", map[string]any{"path": "."}), "not deleted")
	mustFail(t, call(t, s, "move_file", map[string]any{"source": ".", "destination": "x"}), "allowed directory itself")
}

func TestReadOnlyAndAnnotations(t *testing.T) {
	s, root := newTestServer(t, 1)
	write(t, filepath.Join(root, "f"), "f")
	names := map[string]map[string]any{}
	for _, tl := range s.toolList() {
		names[tl["name"].(string)] = tl["annotations"].(map[string]any)
	}
	if len(names) != 18 {
		t.Errorf("%d tools", len(names))
	}
	for name, ann := range names {
		writes := map[string]bool{"write_file": true, "edit_file": true, "create_directory": true, "move_file": true, "delete_file": true}[name]
		if ann["readOnlyHint"] == writes {
			t.Errorf("%s: readOnlyHint %v", name, ann["readOnlyHint"])
		}
	}
	if names["delete_file"]["destructiveHint"] != true || names["create_directory"]["destructiveHint"] != false {
		t.Error("destructiveHint")
	}

	s.readOnly = true
	for _, tl := range s.toolList() {
		if tl["annotations"].(map[string]any)["readOnlyHint"] != true {
			t.Errorf("read-only server offers %s", tl["name"])
		}
	}
	raw, _ := json.Marshal(map[string]any{"path": "f", "content": "x"})
	if _, err := s.call(context.Background(), "write_file", raw); err == nil {
		t.Error("read-only server ran write_file")
	}
	if _, err := s.call(context.Background(), "no_such_tool", nil); err == nil {
		t.Error("unknown tool accepted")
	}
}

func TestResources(t *testing.T) {
	s, root := newTestServer(t, 1)
	for i := 0; i < resourcePage+5; i++ {
		write(t, filepath.Join(root, fmt.Sprintf("f%03d.txt", i)), "t")
	}
	write(t, filepath.Join(root, "hello.txt"), "hello")
	write(t, filepath.Join(root, "bin.dat"), "\x00\x01")
	page, err := s.resourceList("")
	if err != nil {
		t.Fatal(err)
	}
	p := page.(map[string]any)
	if len(p["resources"].([]map[string]any)) != resourcePage || p["nextCursor"] == nil {
		t.Fatalf("first page: %d resources, cursor %v", len(p["resources"].([]map[string]any)), p["nextCursor"])
	}
	page, _ = s.resourceList(p["nextCursor"].(string))
	if p2 := page.(map[string]any); p2["nextCursor"] != nil || len(p2["resources"].([]map[string]any)) == 0 {
		t.Errorf("last page: %v", p2)
	}
	if _, err := s.resourceList("bogus"); err == nil {
		t.Error("bad cursor accepted")
	}
	res, err := s.readResource("file://" + filepath.Join(root, "hello.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if c := res.(map[string]any)["contents"].([]map[string]any)[0]; c["text"] != "hello" || c["mimeType"] != "text/plain" {
		t.Errorf("text resource: %v", c)
	}
	res, _ = s.readResource("file://" + filepath.Join(root, "bin.dat"))
	if c := res.(map[string]any)["contents"].([]map[string]any)[0]; c["blob"] != base64.StdEncoding.EncodeToString([]byte("\x00\x01")) {
		t.Errorf("binary resource: %v", c)
	}
	if _, err := s.readResource("file:///etc/passwd"); err == nil {
		t.Error("resource outside the roots")
	}
}

func TestDiff(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{"a\nb\nc\n", "a\nB\nc\n", "--- a/f\n+++ b/f\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n"},
		{"", "new\n", "--- a/f\n+++ b/f\n@@ -0,0 +1,1 @@\n+new\n"},
		{"x", "y", "--- a/f\n+++ b/f\n@@ -1,1 +1,1 @@\n-x\n\\ No newline at end of file\n+y\n\\ No newline at end of file\n"},
		{"same\n", "same\n", ""},
	} {
		if got := unifiedDiff("f", tc.a, tc.b); got != tc.want {
			t.Errorf("diff %q → %q:\n%s\nwant\n%s", tc.a, tc.b, got, tc.want)
		}
	}
	// Two changes far apart make two hunks.
	var a, b []string
	for i := 0; i < 30; i++ {
		a = append(a, "l")
		b = append(b, "l")
	}
	a[2], b[2] = "x", "y"
	a[25], b[25] = "x", "y"
	if got := unifiedDiff("f", strings.Join(a, "\n")+"\n", strings.Join(b, "\n")+"\n"); strings.Count(got, "@@ -") != 2 {
		t.Errorf("two hunks: %s", got)
	}
}

func TestGlob(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"*.go", "a.go", true},
		{"*.go", "x/y/a.go", true},
		{"*.go", "a.txt", false},
		{"x/*.go", "x/a.go", true},
		{"x/*.go", "x/y/a.go", false},
		{"**/a.go", "a.go", true},
		{"**/a.go", "x/y/a.go", true},
		{"x/**", "x/y/z", true},
		{"x/**/z", "x/z", true},
		{"node_modules", "a/node_modules", true},
		{"**/.git", "p/.git", true},
	} {
		if got := globMatch(tc.pattern, tc.name); got != tc.want {
			t.Errorf("%q ~ %q: %v", tc.pattern, tc.name, got)
		}
	}
}

// On a transactional system the root file system is read-only: a
// directory there can be read, nothing in it changed, and the server says
// why.
func TestReadOnlyFileSystem(t *testing.T) {
	s, rw := newTestServer(t, 2)
	ro := s.dirs[1].path
	write(t, filepath.Join(ro, "f"), "content")
	saved := onReadOnlyFS
	onReadOnlyFS = func(p string) bool { return p == ro }
	defer func() { onReadOnlyFS = saved }()

	if got := mustOK(t, call(t, s, "read_text_file", map[string]any{"path": filepath.Join(ro, "f")})); got != "content" {
		t.Errorf("read: %q", got)
	}
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"write_file", map[string]any{"path": filepath.Join(ro, "f"), "content": "x"}},
		{"edit_file", map[string]any{"path": filepath.Join(ro, "f"), "edits": []map[string]string{{"oldText": "content", "newText": "x"}}}},
		{"create_directory", map[string]any{"path": filepath.Join(ro, "d")}},
		{"move_file", map[string]any{"source": filepath.Join(ro, "f"), "destination": filepath.Join(ro, "g")}},
		{"delete_file", map[string]any{"path": filepath.Join(ro, "f")}},
	} {
		mustFail(t, call(t, s, tc.tool, tc.args), "read-only file system (on a transactional system")
	}
	if b, _ := os.ReadFile(filepath.Join(ro, "f")); string(b) != "content" {
		t.Errorf("changed: %q", b)
	}
	// A dry run only reads.
	mustOK(t, call(t, s, "edit_file", map[string]any{"path": filepath.Join(ro, "f"), "dryRun": true,
		"edits": []map[string]string{{"oldText": "content", "newText": "x"}}}))
	// The other directory is writable.
	mustOK(t, call(t, s, "write_file", map[string]any{"path": filepath.Join(rw, "f"), "content": "x"}))

	r := call(t, s, "list_allowed_directories", map[string]any{})
	if got := r.Structured["readOnly"].([]any); len(got) != 1 || got[0] != ro {
		t.Errorf("readOnly: %v", got)
	}
	if !strings.Contains(r.text(), ro+" (read-only file system)") {
		t.Errorf("text: %q", r.text())
	}
	if !strings.Contains(s.instructions(), "read-only file system") {
		t.Errorf("instructions: %q", s.instructions())
	}
	// EROFS from deeper down (another mount) reads the same.
	tg, _ := s.resolve(filepath.Join(rw, "f"))
	if err := explain(tg, &os.PathError{Op: "open", Path: "f", Err: syscall.EROFS}); !strings.Contains(err.Error(), "transactional-update") {
		t.Errorf("EROFS: %v", err)
	}
}

// btrfs snapshot directories are left out of searches and trees, unless
// the walk starts in one.
func TestSnapshotsSkipped(t *testing.T) {
	s, root := newTestServer(t, 1)
	write(t, filepath.Join(root, "a.go"), "")
	write(t, filepath.Join(root, ".snapshots", "1", "snapshot", "a.go"), "")
	r := call(t, s, "search_files", map[string]any{"path": ".", "pattern": "*.go"})
	if got := r.Structured["matches"].([]any); len(got) != 1 {
		t.Errorf("search entered .snapshots: %v", got)
	}
	if tree := mustOK(t, call(t, s, "directory_tree", map[string]any{"path": "."})); strings.Contains(tree, "snapshot\"") {
		t.Errorf("tree entered .snapshots: %s", tree)
	}
	r = call(t, s, "search_files", map[string]any{"path": ".snapshots/1", "pattern": "*.go"})
	if got := r.Structured["matches"].([]any); len(got) != 1 {
		t.Errorf("search inside .snapshots: %v", got)
	}
}

func TestInstructions(t *testing.T) {
	s, root := newTestServer(t, 1)
	s.about = "The documentation of mcp-gateway."
	got := s.instructions()
	if !strings.HasPrefix(got, "The documentation of mcp-gateway.\n\nFiles below "+root) {
		t.Errorf("instructions: %q", got)
	}
	// Which tool for what, and the limits of a call, as the server has them.
	for _, want := range []string{"outside the allowed directories", "search_text finds lines", "outline_file",
		"read_text_file with offset and limit", "One call reads at most " + size(s.maxRead), "writes at most",
		fmt.Sprintf("at most %d entries", s.maxEntries)} {
		if !strings.Contains(got, want) {
			t.Errorf("instructions without %q: %q", want, got)
		}
	}
	s.readOnly = true
	if strings.Contains(s.instructions(), "writes at most") {
		t.Errorf("read-only instructions name a write limit: %q", s.instructions())
	}
	// The descriptions carry the limits.
	for _, tl := range s.tools() {
		if tl.name == "read_text_file" && !strings.Contains(tl.description, "At most "+size(s.maxRead)) ||
			tl.name == "search_files" && !strings.Contains(tl.description, fmt.Sprintf("at most %d matches", s.maxEntries)) {
			t.Errorf("%s: %q", tl.name, tl.description)
		}
	}
}
