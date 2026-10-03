package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// fileServer holds the allowed directories and limits.
type fileServer struct {
	dirs     []*allowed
	readOnly bool
	// about, if set, opens the instructions: what the files are (e.g.
	// the gateway's documentation).
	about string
	// maxRead bounds what one call returns (file contents, summed over
	// read_multiple_files); maxWrite what one call writes; maxEntries the
	// entries of a listing, tree or search.
	maxRead, maxWrite int64
	maxEntries        int
}

func (s *fileServer) instructions() string {
	mode := ""
	if s.readOnly {
		mode = " Read-only: no tool changes files."
	} else if ro := s.readOnlyDirs(); len(ro) > 0 {
		mode = " On a read-only file system, so nothing there can be changed: " + strings.Join(ro, ", ") + "."
	}
	out := "Files below " + strings.Join(s.dirPaths(), ", ") + ". Paths are absolute, or relative to " +
		s.dirs[0].path + "." + mode
	if s.about != "" {
		out = s.about + "\n\n" + out
	}
	return out
}

// readOnlyDirs lists the allowed directories on read-only file systems.
func (s *fileServer) readOnlyDirs() []string {
	var out []string
	for _, a := range s.dirs {
		if a.readOnly() {
			out = append(out, a.path)
		}
	}
	return out
}

// tool is one tool's definition and handler. Handlers return the result
// (content, and structured content where outputSchema is set) or an error
// that becomes a tool error.
type tool struct {
	name, title, description string
	input                    map[string]any
	output                   map[string]any
	readOnly, destructive    bool
	idempotent               bool
	alias                    string // the tool it is an older name of
	run                      func(s *fileServer, ctx context.Context, args json.RawMessage) (*result, error)
}

type result struct {
	content    []map[string]any
	structured any
}

func text(s string) *result { return &result{content: []map[string]any{{"type": "text", "text": s}}} }

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

var pathArg = str("absolute path, or relative to the first allowed directory")

func (s *fileServer) tools() []tool {
	excludes := map[string]any{"type": "array", "items": map[string]any{"type": "string"},
		"description": "glob patterns of paths to leave out (\"node_modules\", \"**/.git\")"}
	return []tool{
		{name: "read_text_file", title: "Read a text file",
			description: "Read a text file whole, or its first (head) or last (tail) lines. Binary files: read_media_file.",
			input: obj(map[string]any{"path": pathArg,
				"head": map[string]any{"type": "integer", "minimum": 1, "description": "only the first N lines"},
				"tail": map[string]any{"type": "integer", "minimum": 1, "description": "only the last N lines"}}, "path"),
			readOnly: true, idempotent: true, run: readTextFile},
		{name: "read_file", alias: "read_text_file", title: "Read a file",
			description: "Read a text file (older name of read_text_file).",
			input:       obj(map[string]any{"path": pathArg}, "path"), readOnly: true, idempotent: true, run: readTextFile},
		{name: "read_media_file", title: "Read an image, audio or other binary file",
			description: "Read a file as base64 with its MIME type: images and audio as such, other files as a binary resource.",
			input:       obj(map[string]any{"path": pathArg}, "path"), readOnly: true, idempotent: true, run: readMediaFile},
		{name: "read_multiple_files", title: "Read several text files",
			description: "Read several text files at once; a file that cannot be read does not fail the others.",
			input: obj(map[string]any{"paths": map[string]any{"type": "array", "minItems": 1,
				"items": map[string]any{"type": "string"}, "description": "the files"}}, "paths"),
			readOnly: true, idempotent: true, run: readMultipleFiles},
		{name: "list_directory", title: "List a directory",
			description: "List a directory's entries, each marked [DIR], [FILE] or [LINK].",
			input:       obj(map[string]any{"path": pathArg}, "path"), readOnly: true, idempotent: true, run: listDirectory},
		{name: "list_dir", alias: "list_directory", title: "List a directory",
			description: "List a directory's entry names, one per line (older form of list_directory).",
			input:       obj(map[string]any{"path": pathArg}, "path"), readOnly: true, idempotent: true, run: listDir},
		{name: "list_directory_with_sizes", title: "List a directory with sizes",
			description: "List a directory's entries with their sizes and the total.",
			input: obj(map[string]any{"path": pathArg, "sortBy": map[string]any{"type": "string",
				"enum": []string{"name", "size"}, "description": "order: name (default) or size, largest first"}}, "path"),
			readOnly: true, idempotent: true, run: listDirectoryWithSizes},
		{name: "directory_tree", title: "Directory tree",
			description: "The directory tree below a path as JSON: [{name, type, children}]; symbolic links are not " +
				"followed, btrfs .snapshots directories not entered (give a path inside one to look there).",
			input:    obj(map[string]any{"path": pathArg, "excludePatterns": excludes}, "path"),
			readOnly: true, idempotent: true, run: directoryTree},
		{name: "search_files", title: "Find files",
			description: "Find files and directories below a path whose path matches a glob pattern: \"*.go\" " +
				"matches names at any depth, \"src/**/*.go\" paths relative to the start. btrfs .snapshots " +
				"directories are not searched unless the path is inside one.",
			input: obj(map[string]any{"path": pathArg, "pattern": str("glob pattern"), "excludePatterns": excludes},
				"path", "pattern"),
			output: obj(map[string]any{"matches": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"truncated": map[string]any{"type": "boolean"}}, "matches", "truncated"),
			readOnly: true, idempotent: true, run: searchFiles},
		{name: "get_file_info", title: "File information",
			description: "Type, size, permissions and times of a file or directory.",
			input:       obj(map[string]any{"path": pathArg}, "path"),
			output: obj(map[string]any{"path": map[string]any{"type": "string"}, "type": map[string]any{"type": "string"},
				"size": map[string]any{"type": "integer"}, "permissions": map[string]any{"type": "string"},
				"modified": map[string]any{"type": "string"}, "accessed": map[string]any{"type": "string"},
				"symlink": map[string]any{"type": "boolean"}, "mimeType": map[string]any{"type": "string"}},
				"path", "type", "size", "permissions", "modified", "symlink"),
			readOnly: true, idempotent: true, run: getFileInfo},
		{name: "list_allowed_directories", title: "Allowed directories",
			description: "The directories this server works in.",
			input:       obj(map[string]any{}),
			output: obj(map[string]any{"directories": map[string]any{"type": "array",
				"items": map[string]any{"type": "string"}}, "readOnly": map[string]any{"type": "array",
				"items": map[string]any{"type": "string"}, "description": "those on a read-only file system"}},
				"directories", "readOnly"),
			readOnly: true, idempotent: true, run: listAllowed},
		{name: "write_file", title: "Write a file",
			description: "Create a file, or replace its contents. The file is replaced at once (a temporary file renamed " +
				"over it); its directory must exist.",
			input:       obj(map[string]any{"path": pathArg, "content": str("the new contents")}, "path", "content"),
			destructive: true, idempotent: true, run: writeFile},
		{name: "edit_file", title: "Edit a file",
			description: "Replace text in a file: each oldText must occur exactly once. Returns a diff; with dryRun the " +
				"file is not changed.",
			input: obj(map[string]any{"path": pathArg,
				"edits": map[string]any{"type": "array", "minItems": 1, "items": obj(map[string]any{
					"oldText": str("text to replace, exactly as in the file"), "newText": str("its replacement")},
					"oldText", "newText")},
				"dryRun": map[string]any{"type": "boolean", "description": "only show the diff"}}, "path", "edits"),
			destructive: true, run: editFile},
		{name: "create_directory", title: "Create a directory",
			description: "Create a directory and its missing parents; an existing one is left as it is.",
			input:       obj(map[string]any{"path": pathArg}, "path"), idempotent: true, run: createDirectory},
		{name: "move_file", title: "Move or rename",
			description: "Move or rename a file or directory within one allowed directory; an existing destination is not replaced.",
			input:       obj(map[string]any{"source": pathArg, "destination": pathArg}, "source", "destination"),
			run:         moveFile},
		{name: "delete_file", title: "Delete a file",
			description: "Delete a file, or an empty directory.",
			input:       obj(map[string]any{"path": pathArg}, "path"), destructive: true, idempotent: true, run: deleteFile},
	}
}

func (s *fileServer) find(name string) (tool, bool) {
	for _, t := range s.tools() {
		if t.name == name && (t.readOnly || !s.readOnly) {
			return t, true
		}
	}
	return tool{}, false
}

func (s *fileServer) toolList() []map[string]any {
	var out []map[string]any
	for _, t := range s.tools() {
		if s.readOnly && !t.readOnly {
			continue
		}
		m := map[string]any{"name": t.name, "title": t.title, "description": t.description, "inputSchema": t.input,
			"annotations": map[string]any{"title": t.title, "readOnlyHint": t.readOnly,
				"destructiveHint": t.destructive, "idempotentHint": t.idempotent, "openWorldHint": false}}
		if t.output != nil {
			m["outputSchema"] = t.output
		}
		out = append(out, m)
	}
	return out
}

func (s *fileServer) call(ctx context.Context, name string, args json.RawMessage) (any, error) {
	t, ok := s.find(name)
	if !ok {
		return nil, &rpcError{codeInvalidParams, "unknown tool " + strconv.Quote(name)}
	}
	if len(args) == 0 || string(args) == "null" {
		args = json.RawMessage("{}")
	}
	res, err := t.run(s, ctx, args)
	if err != nil {
		return map[string]any{"content": []map[string]any{{"type": "text", "text": err.Error()}}, "isError": true}, nil
	}
	out := map[string]any{"content": res.content, "isError": false}
	if res.structured != nil {
		out["structuredContent"] = res.structured
	}
	return out, nil
}

// decode reads a tool's arguments into v, refusing unknown ones.
func decode(args json.RawMessage, v any) error {
	d := json.NewDecoder(bytes.NewReader(args))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("invalid arguments: %v", err)
	}
	return nil
}

type pathArgs struct {
	Path string `json:"path"`
}

func (s *fileServer) target(args json.RawMessage, v any, p *string) (target, error) {
	if err := decode(args, v); err != nil {
		return target{}, err
	}
	return s.resolve(*p)
}

// --- reading ---------------------------------------------------------------

func readTextFile(s *fileServer, _ context.Context, args json.RawMessage) (*result, error) {
	var a struct {
		Path string `json:"path"`
		Head int    `json:"head"`
		Tail int    `json:"tail"`
	}
	t, err := s.target(args, &a, &a.Path)
	if err != nil {
		return nil, err
	}
	if a.Head < 0 || a.Tail < 0 || (a.Head > 0 && a.Tail > 0) {
		return nil, errors.New("give head or tail (a positive number of lines), not both")
	}
	b, err := s.readText(t, a.Head, a.Tail, s.maxRead)
	if err != nil {
		return nil, err
	}
	return text(string(b)), nil
}

// readText reads t (all, the first head or the last tail lines) as text,
// up to max bytes.
func (s *fileServer) readText(t target, head, tail int, max int64) ([]byte, error) {
	root, err := t.dir.open()
	if err != nil {
		return nil, explain(t, err)
	}
	f, err := root.Open(t.rel)
	if err != nil {
		return nil, explain(t, err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, explain(t, err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("%s: is a directory (list_directory lists it)", t.full)
	}
	var b []byte
	switch {
	case head > 0:
		b, err = headLines(f, head, max)
	case tail > 0:
		b, err = tailLines(f, fi.Size(), tail, max)
	default:
		if fi.Size() > max {
			return nil, fmt.Errorf("%s: %s, more than the %s one call may read: read parts of it with head or tail",
				t.full, size(fi.Size()), size(max))
		}
		b, err = readLimited(f, max)
	}
	if errors.Is(err, errTooLarge) {
		return nil, fmt.Errorf("%s: the lines asked for exceed the %s one call may read", t.full, size(max))
	}
	if err != nil {
		return nil, explain(t, err)
	}
	if isBinary(b) {
		return nil, fmt.Errorf("%s: not a text file (%s): read it with read_media_file", t.full, mimeType(t.rel, b))
	}
	return b, nil
}

func headLines(r io.Reader, n int, max int64) ([]byte, error) {
	br := bufio.NewReader(io.LimitReader(r, max+1))
	var out []byte
	for i := 0; i < n; i++ {
		line, err := br.ReadBytes('\n')
		out = append(out, line...)
		if int64(len(out)) > max {
			return nil, errTooLarge
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// tailLines reads the last n lines of a file of the given size, reading
// backwards in blocks.
func tailLines(f io.ReaderAt, size int64, n int, max int64) ([]byte, error) {
	const block = 64 << 10
	var buf []byte
	pos := size
	for pos > 0 {
		step := int64(block)
		if step > pos {
			step = pos
		}
		pos -= step
		chunk := make([]byte, step)
		if _, err := f.ReadAt(chunk, pos); err != nil && err != io.EOF {
			return nil, err
		}
		buf = append(chunk, buf...)
		// Lines: a trailing newline ends the last line, it does not start one.
		body := bytes.TrimSuffix(buf, []byte("\n"))
		if bytes.Count(body, []byte("\n")) >= n {
			idx := len(body)
			for i := 0; i < n; i++ {
				idx = bytes.LastIndexByte(body[:idx], '\n')
			}
			buf = buf[idx+1:]
			break
		}
		if int64(len(buf)) > max {
			return nil, errTooLarge
		}
	}
	if int64(len(buf)) > max {
		return nil, errTooLarge
	}
	return buf, nil
}

func isBinary(b []byte) bool {
	sample := b
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	return bytes.IndexByte(sample, 0) >= 0 || !utf8.Valid(trimPartialRune(sample))
}

// trimPartialRune drops an incomplete UTF-8 sequence at the end of a
// sample cut from a longer text.
func trimPartialRune(b []byte) []byte {
	for i := 1; i <= 3 && i <= len(b); i++ {
		if r, _ := utf8.DecodeLastRune(b[:len(b)-i+1]); r != utf8.RuneError {
			return b[:len(b)-i+1]
		}
	}
	return b
}

func mimeType(name string, data []byte) string {
	if t := mime.TypeByExtension(filepath.Ext(name)); t != "" {
		return strings.Split(t, ";")[0]
	}
	return strings.Split(http.DetectContentType(data), ";")[0]
}

func readMediaFile(s *fileServer, _ context.Context, args json.RawMessage) (*result, error) {
	var a pathArgs
	t, err := s.target(args, &a, &a.Path)
	if err != nil {
		return nil, err
	}
	b, err := s.readBytes(t)
	if err != nil {
		return nil, err
	}
	mt := mimeType(t.rel, b)
	data := base64.StdEncoding.EncodeToString(b)
	var c map[string]any
	switch {
	case strings.HasPrefix(mt, "image/"):
		c = map[string]any{"type": "image", "data": data, "mimeType": mt}
	case strings.HasPrefix(mt, "audio/"):
		c = map[string]any{"type": "audio", "data": data, "mimeType": mt}
	default:
		c = map[string]any{"type": "resource", "resource": map[string]any{"uri": fileURI(t.full), "mimeType": mt, "blob": data}}
	}
	return &result{content: []map[string]any{c}}, nil
}

// readBytes reads t whole, up to the read limit; base64 makes it a third
// larger, which the limit leaves room for.
func (s *fileServer) readBytes(t target) ([]byte, error) {
	root, err := t.dir.open()
	if err != nil {
		return nil, explain(t, err)
	}
	f, err := root.Open(t.rel)
	if err != nil {
		return nil, explain(t, err)
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err == nil && fi.IsDir() {
		return nil, fmt.Errorf("%s: is a directory", t.full)
	}
	b, err := readLimited(f, s.maxRead)
	if errors.Is(err, errTooLarge) {
		return nil, fmt.Errorf("%s: more than the %s one call may read", t.full, size(s.maxRead))
	}
	if err != nil {
		return nil, explain(t, err)
	}
	return b, nil
}

func readMultipleFiles(s *fileServer, ctx context.Context, args json.RawMessage) (*result, error) {
	var a struct {
		Paths []string `json:"paths"`
	}
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	if len(a.Paths) == 0 {
		return nil, errors.New("paths: give at least one file")
	}
	budget := s.maxRead
	var parts []string
	for _, p := range a.Paths {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		t, err := s.resolve(p)
		if err == nil {
			var b []byte
			b, err = s.readText(t, 0, 0, budget)
			if err == nil {
				budget -= int64(len(b))
				parts = append(parts, t.full+":\n"+string(b))
				continue
			}
		}
		parts = append(parts, p+": error: "+err.Error())
	}
	return text(strings.Join(parts, "\n---\n")), nil
}

// readDir lists t's entries, sorted by name, up to the entry limit.
func (s *fileServer) readDir(t target) ([]fs.DirEntry, bool, error) {
	root, err := t.dir.open()
	if err != nil {
		return nil, false, explain(t, err)
	}
	d, err := root.Open(t.rel)
	if err != nil {
		return nil, false, explain(t, err)
	}
	defer func() { _ = d.Close() }()
	entries, err := d.ReadDir(-1)
	if err != nil {
		return nil, false, explain(t, err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	if len(entries) > s.maxEntries {
		return entries[:s.maxEntries], true, nil
	}
	return entries, false, nil
}

func kind(e fs.DirEntry) string {
	switch {
	case e.Type()&fs.ModeSymlink != 0:
		return "LINK"
	case e.IsDir():
		return "DIR"
	}
	return "FILE"
}

func truncatedNote(n int) string {
	return fmt.Sprintf("(only the first %d entries)", n)
}

func listDirectory(s *fileServer, _ context.Context, args json.RawMessage) (*result, error) {
	var a pathArgs
	t, err := s.target(args, &a, &a.Path)
	if err != nil {
		return nil, err
	}
	entries, truncated, err := s.readDir(t)
	if err != nil {
		return nil, err
	}
	lines := make([]string, 0, len(entries)+1)
	for _, e := range entries {
		lines = append(lines, "["+kind(e)+"] "+e.Name())
	}
	if truncated {
		lines = append(lines, truncatedNote(s.maxEntries))
	}
	return text(strings.Join(lines, "\n")), nil
}

func listDir(s *fileServer, _ context.Context, args json.RawMessage) (*result, error) {
	var a pathArgs
	t, err := s.target(args, &a, &a.Path)
	if err != nil {
		return nil, err
	}
	entries, _, err := s.readDir(t)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name()
	}
	return text(strings.Join(names, "\n")), nil
}

func listDirectoryWithSizes(s *fileServer, _ context.Context, args json.RawMessage) (*result, error) {
	var a struct {
		Path   string `json:"path"`
		SortBy string `json:"sortBy"`
	}
	t, err := s.target(args, &a, &a.Path)
	if err != nil {
		return nil, err
	}
	if a.SortBy != "" && a.SortBy != "name" && a.SortBy != "size" {
		return nil, errors.New("sortBy: name or size")
	}
	entries, truncated, err := s.readDir(t)
	if err != nil {
		return nil, err
	}
	type row struct {
		e    fs.DirEntry
		size int64
	}
	rows := make([]row, len(entries))
	var total int64
	files, dirs := 0, 0
	for i, e := range entries {
		rows[i].e = e
		if fi, err := e.Info(); err == nil && !e.IsDir() {
			rows[i].size = fi.Size()
			total += fi.Size()
		}
		if e.IsDir() {
			dirs++
		} else {
			files++
		}
	}
	if a.SortBy == "size" {
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].size > rows[j].size })
	}
	var b strings.Builder
	for _, r := range rows {
		sz := ""
		if !r.e.IsDir() {
			sz = size(r.size)
		}
		fmt.Fprintf(&b, "[%s] %-40s %10s\n", kind(r.e), r.e.Name(), sz)
	}
	if truncated {
		b.WriteString(truncatedNote(s.maxEntries) + "\n")
	}
	fmt.Fprintf(&b, "\n%d files, %d directories, %s in files", files, dirs, size(total))
	return text(b.String()), nil
}

// walk visits the entries below t (not t itself) in lexical order without
// following symbolic links, skipping excluded paths, until visit returns
// false or the context ends.
func (s *fileServer) walk(ctx context.Context, t target, excludes []string, visit func(rel string, e fs.DirEntry) bool) error {
	for _, p := range excludes {
		if !validGlob(p) {
			return fmt.Errorf("excludePatterns: %q is not a valid pattern", p)
		}
	}
	root, err := t.dir.open()
	if err != nil {
		return explain(t, err)
	}
	if fi, err := root.Stat(t.rel); err != nil {
		return explain(t, err)
	} else if !fi.IsDir() {
		return fmt.Errorf("%s: not a directory", t.full)
	}
	stop := errors.New("stop")
	err = fs.WalkDir(root.FS(), t.rel, func(p string, e fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if p == t.rel {
				return err
			}
			return nil // unreadable below: skip it
		}
		if p == t.rel {
			return nil
		}
		rel := strings.TrimPrefix(p, t.rel+"/")
		if t.rel == "." {
			rel = p
		}
		// btrfs snapshots (snapper): a copy of the tree per snapshot. Not
		// entered unless the walk starts in one.
		if e.IsDir() && e.Name() == ".snapshots" && !strings.Contains(t.full+"/", "/.snapshots/") {
			return fs.SkipDir
		}
		for _, x := range excludes {
			if globMatch(x, rel) {
				if e.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}
		if !visit(rel, e) {
			return stop
		}
		return nil
	})
	if errors.Is(err, stop) {
		return nil
	}
	if err != nil && ctx.Err() == nil {
		return explain(t, err)
	}
	return err
}

func directoryTree(s *fileServer, ctx context.Context, args json.RawMessage) (*result, error) {
	var a struct {
		Path            string   `json:"path"`
		ExcludePatterns []string `json:"excludePatterns"`
	}
	t, err := s.target(args, &a, &a.Path)
	if err != nil {
		return nil, err
	}
	type node struct {
		Name     string  `json:"name"`
		Type     string  `json:"type"`
		Children []*node `json:"children,omitempty"`
	}
	top := &node{Type: "directory"}
	dirs := map[string]*node{"": top}
	count, truncated := 0, false
	err = s.walk(ctx, t, a.ExcludePatterns, func(rel string, e fs.DirEntry) bool {
		if count >= s.maxEntries {
			truncated = true
			return false
		}
		count++
		n := &node{Name: path.Base(rel), Type: "file"}
		switch {
		case e.Type()&fs.ModeSymlink != 0:
			n.Type = "symlink"
		case e.IsDir():
			n.Type = "directory"
			n.Children = []*node{}
			dirs[rel] = n
		}
		parentDir := path.Dir(rel)
		if parentDir == "." {
			parentDir = ""
		}
		if p := dirs[parentDir]; p != nil {
			p.Children = append(p.Children, n)
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	b, _ := json.MarshalIndent(top.Children, "", "  ")
	res := text(string(b))
	if truncated {
		res.content = append(res.content, map[string]any{"type": "text", "text": truncatedNote(s.maxEntries)})
	}
	return res, nil
}

func searchFiles(s *fileServer, ctx context.Context, args json.RawMessage) (*result, error) {
	var a struct {
		Path            string   `json:"path"`
		Pattern         string   `json:"pattern"`
		ExcludePatterns []string `json:"excludePatterns"`
	}
	t, err := s.target(args, &a, &a.Path)
	if err != nil {
		return nil, err
	}
	if !validGlob(a.Pattern) {
		return nil, fmt.Errorf("pattern: %q is not a valid glob pattern", a.Pattern)
	}
	matches := []string{}
	truncated := false
	err = s.walk(ctx, t, a.ExcludePatterns, func(rel string, _ fs.DirEntry) bool {
		if !globMatch(a.Pattern, rel) {
			return true
		}
		if len(matches) >= s.maxEntries {
			truncated = true
			return false
		}
		matches = append(matches, filepath.Join(t.full, rel))
		return true
	})
	if err != nil {
		return nil, err
	}
	body := strings.Join(matches, "\n")
	switch {
	case len(matches) == 0:
		body = "no matches"
	case truncated:
		body += "\n" + truncatedNote(s.maxEntries)
	}
	res := text(body)
	res.structured = map[string]any{"matches": matches, "truncated": truncated}
	return res, nil
}

func getFileInfo(s *fileServer, _ context.Context, args json.RawMessage) (*result, error) {
	var a pathArgs
	t, err := s.target(args, &a, &a.Path)
	if err != nil {
		return nil, err
	}
	root, err := t.dir.open()
	if err != nil {
		return nil, explain(t, err)
	}
	lfi, err := root.Lstat(t.rel)
	if err != nil {
		return nil, explain(t, err)
	}
	symlink := lfi.Mode()&fs.ModeSymlink != 0
	fi := lfi
	if symlink {
		if tfi, err := root.Stat(t.rel); err == nil {
			fi = tfi
		}
	}
	typ := "other"
	switch {
	case fi.Mode().IsRegular():
		typ = "file"
	case fi.IsDir():
		typ = "directory"
	case fi.Mode()&fs.ModeSymlink != 0:
		typ = "symlink" // to something outside the allowed directories, or missing
	}
	info := map[string]any{"path": t.full, "type": typ, "size": fi.Size(),
		"permissions": fmt.Sprintf("%04o", fi.Mode().Perm()), "modified": fi.ModTime().UTC().Format(time.RFC3339),
		"symlink": symlink}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		info["accessed"] = time.Unix(st.Atim.Sec, st.Atim.Nsec).UTC().Format(time.RFC3339)
	}
	if typ == "file" {
		head := make([]byte, 512)
		if f, err := root.Open(t.rel); err == nil {
			n, _ := f.Read(head)
			_ = f.Close()
			info["mimeType"] = mimeType(t.rel, head[:n])
		}
	}
	var b strings.Builder
	for _, k := range []string{"path", "type", "size", "permissions", "modified", "accessed", "symlink", "mimeType"} {
		if v, ok := info[k]; ok {
			fmt.Fprintf(&b, "%s: %v\n", k, v)
		}
	}
	res := text(strings.TrimSuffix(b.String(), "\n"))
	res.structured = info
	return res, nil
}

func listAllowed(s *fileServer, _ context.Context, args json.RawMessage) (*result, error) {
	var a struct{}
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	ro := s.readOnlyDirs()
	lines := []string{"Allowed directories:"}
	for _, a := range s.dirs {
		line := a.path
		if a.readOnly() {
			line += " (read-only file system)"
		}
		lines = append(lines, line)
	}
	res := text(strings.Join(lines, "\n"))
	if ro == nil {
		ro = []string{}
	}
	res.structured = map[string]any{"directories": s.dirPaths(), "readOnly": ro}
	return res, nil
}

// --- changing --------------------------------------------------------------

func writeFile(s *fileServer, _ context.Context, args json.RawMessage) (*result, error) {
	var a struct {
		Path    string  `json:"path"`
		Content *string `json:"content"`
	}
	t, err := s.target(args, &a, &a.Path)
	if err != nil {
		return nil, err
	}
	if a.Content == nil {
		return nil, errors.New("content is required")
	}
	if err := writable(t); err != nil {
		return nil, err
	}
	if int64(len(*a.Content)) > s.maxWrite {
		return nil, fmt.Errorf("%s: %s, more than the %s one call may write", t.full, size(int64(len(*a.Content))), size(s.maxWrite))
	}
	if err := writeAtomic(t, []byte(*a.Content)); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s: its directory does not exist (create_directory creates it)", t.full)
		}
		return nil, explain(t, err)
	}
	return text(fmt.Sprintf("wrote %s (%s)", t.full, size(int64(len(*a.Content))))), nil
}

func editFile(s *fileServer, _ context.Context, args json.RawMessage) (*result, error) {
	var a struct {
		Path  string `json:"path"`
		Edits []struct {
			OldText string `json:"oldText"`
			NewText string `json:"newText"`
		} `json:"edits"`
		DryRun bool `json:"dryRun"`
	}
	t, err := s.target(args, &a, &a.Path)
	if err != nil {
		return nil, err
	}
	if len(a.Edits) == 0 {
		return nil, errors.New("edits: give at least one")
	}
	if !a.DryRun {
		if err := writable(t); err != nil {
			return nil, err
		}
	}
	old, err := s.readText(t, 0, 0, s.maxWrite)
	if err != nil {
		return nil, err
	}
	content := string(old)
	crlf := strings.Contains(content, "\r\n")
	for i, e := range a.Edits {
		oldText, newText := e.OldText, e.NewText
		if crlf && !strings.Contains(oldText, "\r\n") {
			oldText = strings.ReplaceAll(oldText, "\n", "\r\n")
			newText = strings.ReplaceAll(newText, "\n", "\r\n")
		}
		if oldText == "" {
			return nil, fmt.Errorf("edit %d: oldText is empty", i+1)
		}
		switch n := strings.Count(content, oldText); n {
		case 1:
			content = strings.Replace(content, oldText, newText, 1)
		case 0:
			return nil, fmt.Errorf("edit %d: oldText not found in %s (it must match exactly, whitespace included)", i+1, t.full)
		default:
			return nil, fmt.Errorf("edit %d: oldText occurs %d times in %s: include more of the surrounding text", i+1, n, t.full)
		}
	}
	if int64(len(content)) > s.maxWrite {
		return nil, fmt.Errorf("%s: the edited file would exceed the %s one call may write", t.full, size(s.maxWrite))
	}
	diff := unifiedDiff(filepath.ToSlash(t.rel), string(old), content)
	if diff == "" {
		return text("no changes"), nil
	}
	if !a.DryRun {
		if err := writeAtomic(t, []byte(content)); err != nil {
			return nil, explain(t, err)
		}
	}
	return text(diff), nil
}

func createDirectory(s *fileServer, _ context.Context, args json.RawMessage) (*result, error) {
	var a pathArgs
	t, err := s.target(args, &a, &a.Path)
	if err != nil {
		return nil, err
	}
	if err := writable(t); err != nil {
		return nil, err
	}
	if err := mkdirAll(t); err != nil {
		return nil, explain(t, err)
	}
	return text("created " + t.full), nil
}

func moveFile(s *fileServer, _ context.Context, args json.RawMessage) (*result, error) {
	var a struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
	}
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	src, err := s.resolve(a.Source)
	if err != nil {
		return nil, err
	}
	dst, err := s.resolve(a.Destination)
	if err != nil {
		return nil, err
	}
	if err := writable(src); err != nil {
		return nil, err
	}
	if err := move(src, dst); err != nil {
		return nil, err
	}
	return text("moved " + src.full + " to " + dst.full), nil
}

func deleteFile(s *fileServer, _ context.Context, args json.RawMessage) (*result, error) {
	var a pathArgs
	t, err := s.target(args, &a, &a.Path)
	if err != nil {
		return nil, err
	}
	if t.isRoot() {
		return nil, fmt.Errorf("%s: an allowed directory itself is not deleted", t.full)
	}
	if err := writable(t); err != nil {
		return nil, err
	}
	root, err := t.dir.open()
	if err != nil {
		return nil, explain(t, err)
	}
	if err := root.Remove(t.rel); err != nil {
		return nil, explain(t, err)
	}
	return text("deleted " + t.full), nil
}

// --- resources -------------------------------------------------------------

const resourcePage = 100

func fileURI(p string) string { return "file://" + p }

// resourceList lists the files directly in the allowed directories, a
// page at a time; the cursor is the index of the next one.
func (s *fileServer) resourceList(cursor string) (any, error) {
	start := 0
	if cursor != "" {
		n, err := strconv.Atoi(cursor)
		if err != nil || n < 0 {
			return nil, &rpcError{codeInvalidParams, "invalid cursor"}
		}
		start = n
	}
	var all []map[string]any
	for _, d := range s.dirs {
		root, err := d.open()
		if err != nil {
			continue
		}
		f, err := root.Open(".")
		if err != nil {
			continue
		}
		entries, _ := f.ReadDir(-1)
		_ = f.Close()
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			r := map[string]any{"uri": fileURI(filepath.Join(d.path, e.Name())), "name": e.Name(),
				"mimeType": mimeType(e.Name(), nil)}
			if fi, err := e.Info(); err == nil {
				r["size"] = fi.Size()
			}
			all = append(all, r)
		}
	}
	if start > len(all) {
		start = len(all)
	}
	end := start + resourcePage
	out := map[string]any{}
	if end < len(all) {
		out["nextCursor"] = strconv.Itoa(end)
	} else {
		end = len(all)
	}
	out["resources"] = append([]map[string]any{}, all[start:end]...)
	return out, nil
}

func (s *fileServer) resourceTemplates() []map[string]any {
	var out []map[string]any
	for _, d := range s.dirs {
		out = append(out, map[string]any{"uriTemplate": fileURI(strings.TrimSuffix(d.path, "/")) + "/{+path}",
			"name": "file", "title": "A file below " + d.path, "description": "a file below " + d.path})
	}
	return out
}

func (s *fileServer) readResource(uri string) (any, error) {
	if !strings.HasPrefix(uri, "file://") {
		return nil, &rpcError{codeNoResource, "resource not found"}
	}
	t, err := s.resolve(strings.TrimPrefix(uri, "file://"))
	if err != nil {
		return nil, &rpcError{codeNoResource, "resource not found"}
	}
	b, err := s.readBytes(t)
	if err != nil {
		return nil, &rpcError{codeNoResource, "resource not found: " + err.Error()}
	}
	mt := mimeType(t.rel, b)
	c := map[string]any{"uri": uri, "mimeType": mt}
	if isBinary(b) {
		c["blob"] = base64.StdEncoding.EncodeToString(b)
	} else {
		c["text"] = string(b)
	}
	return map[string]any{"contents": []map[string]any{c}}, nil
}

// size formats a byte count.
func size(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
