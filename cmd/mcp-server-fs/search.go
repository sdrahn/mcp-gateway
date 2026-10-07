package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// search_text finds the lines of text files below a path (or in one file)
// that contain a text or match a regular expression, with a few lines of
// context: an agent reads what it needs (read_text_file with offset and
// limit) instead of whole files (docs/architecture.md, roadmap step 27).

const (
	defaultContext    = 2
	maxContext        = 10
	defaultMaxResults = 50
	maxMaxResults     = 500
	// maxLineShown cuts long lines (minified files) in the output.
	maxLineShown = 400
)

// textMatch is a matching line.
type textMatch struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

func searchTextTool() tool {
	return tool{name: "search_text", title: "Search text in files",
		description: "Find the lines of text files below a path, or in one file, that contain a text (or match a " +
			"regular expression with regexp: true), case-insensitive unless caseSensitive. Gives each match " +
			"with its file, line number and context lines; read more around it with read_text_file (offset, limit). " +
			"Symbolic links are not followed, binary files and btrfs .snapshots directories are skipped.",
		input: obj(map[string]any{"path": pathArg,
			"query":         str("the text to find, or a regular expression (RE2 syntax) with regexp: true"),
			"regexp":        map[string]any{"type": "boolean", "description": "query is a regular expression"},
			"caseSensitive": map[string]any{"type": "boolean", "description": "match case (default: ignore it)"},
			"context": map[string]any{"type": "integer", "minimum": 0, "maximum": maxContext,
				"description": fmt.Sprintf("lines shown before and after each match (default %d)", defaultContext)},
			"maxResults": map[string]any{"type": "integer", "minimum": 1, "maximum": maxMaxResults,
				"description": fmt.Sprintf("matching lines at most (default %d)", defaultMaxResults)},
			"excludePatterns": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
				"description": "glob patterns of paths to leave out (\"node_modules\", \"**/.git\")"},
		}, "path", "query"),
		output: obj(map[string]any{
			"matches": map[string]any{"type": "array", "items": obj(map[string]any{
				"path": map[string]any{"type": "string"}, "line": map[string]any{"type": "integer"},
				"text": map[string]any{"type": "string"}}, "path", "line", "text")},
			"truncated": map[string]any{"type": "boolean"}}, "matches", "truncated"),
		readOnly: true, idempotent: true, run: searchText}
}

func searchText(s *fileServer, ctx context.Context, args json.RawMessage) (*result, error) {
	a := struct {
		Path            string   `json:"path"`
		Query           string   `json:"query"`
		Regexp          bool     `json:"regexp"`
		CaseSensitive   bool     `json:"caseSensitive"`
		Context         *int     `json:"context"`
		MaxResults      int      `json:"maxResults"`
		ExcludePatterns []string `json:"excludePatterns"`
	}{}
	t, err := s.target(args, &a, &a.Path)
	if err != nil {
		return nil, err
	}
	if a.Query == "" {
		return nil, errors.New("query: give the text to find")
	}
	around := defaultContext
	if a.Context != nil {
		around = *a.Context
	}
	if around < 0 || around > maxContext {
		return nil, fmt.Errorf("context: from 0 to %d lines", maxContext)
	}
	limit := a.MaxResults
	if limit == 0 {
		limit = defaultMaxResults
	}
	if limit < 0 || limit > maxMaxResults {
		return nil, fmt.Errorf("maxResults: from 1 to %d", maxMaxResults)
	}
	match, err := matcher(a.Query, a.Regexp, a.CaseSensitive)
	if err != nil {
		return nil, err
	}

	sr := &textSearch{s: s, match: match, around: around, limit: limit, matches: []textMatch{}}
	root, err := t.dir.open()
	if err != nil {
		return nil, explain(t, err)
	}
	fi, err := root.Stat(t.rel)
	if err != nil {
		return nil, explain(t, err)
	}
	if fi.IsDir() {
		err = s.walk(ctx, t, a.ExcludePatterns, func(rel string, e fs.DirEntry) bool {
			if !e.Type().IsRegular() {
				return true // directories are walked; links not followed
			}
			return sr.file(t, filepath.Join(t.rel, rel), filepath.Join(t.full, rel))
		})
		if err != nil {
			return nil, err
		}
	} else {
		sr.file(t, t.rel, t.full)
	}

	body := strings.TrimRight(sr.out.String(), "\n")
	switch {
	case len(sr.matches) == 0 && !sr.truncated:
		body = "no matches"
	case sr.truncated:
		body += fmt.Sprintf("\n(stopped after %d matching lines: narrow the query or the path)", len(sr.matches))
	}
	res := text(body)
	res.structured = map[string]any{"matches": sr.matches, "truncated": sr.truncated}
	return res, nil
}

// matcher returns whether a line matches query.
func matcher(query string, isRegexp, caseSensitive bool) (func(string) bool, error) {
	if isRegexp {
		if !caseSensitive {
			query = "(?i)" + query
		}
		re, err := regexp.Compile(query)
		if err != nil {
			return nil, fmt.Errorf("query: not a valid regular expression: %v", err)
		}
		return re.MatchString, nil
	}
	if caseSensitive {
		return func(l string) bool { return strings.Contains(l, query) }, nil
	}
	q := strings.ToLower(query)
	return func(l string) bool { return strings.Contains(strings.ToLower(l), q) }, nil
}

// textSearch collects matches and their context, up to limit matching
// lines and maxRead bytes of output.
type textSearch struct {
	s         *fileServer
	match     func(string) bool
	around    int
	limit     int
	matches   []textMatch
	out       strings.Builder
	truncated bool
}

// file searches the file rel (shown as full); it returns false when the
// search is to stop.
func (sr *textSearch) file(t target, rel, full string) bool {
	root, err := t.dir.open()
	if err != nil {
		return true
	}
	fi, err := root.Stat(rel)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > sr.s.maxRead {
		return true // unreadable, or larger than one read: skipped
	}
	f, err := root.Open(rel)
	if err != nil {
		return true
	}
	defer func() { _ = f.Close() }()
	b, err := readLimited(f, sr.s.maxRead)
	if err != nil || isBinary(b) {
		return true
	}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 64<<10), len(b)+1)
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	var hits []int
	for i, l := range lines {
		if sr.match(l) {
			hits = append(hits, i)
		}
	}
	if len(hits) == 0 {
		return true
	}
	fmt.Fprintf(&sr.out, "%s\n", full)
	shownTo := -1 // last line index written
	for _, h := range hits {
		if len(sr.matches) >= sr.limit || int64(sr.out.Len()) > sr.s.maxRead {
			sr.truncated = true
			return false
		}
		from, to := max(h-sr.around, 0), min(h+sr.around, len(lines)-1)
		if shownTo >= 0 && from > shownTo+1 {
			sr.out.WriteString("--\n")
		}
		for i := max(from, shownTo+1); i <= to; i++ {
			sep := "-"
			if sr.match(lines[i]) {
				sep = ":"
			}
			fmt.Fprintf(&sr.out, "%d%s %s\n", i+1, sep, cut(lines[i]))
		}
		shownTo = max(shownTo, to)
		sr.matches = append(sr.matches, textMatch{Path: full, Line: h + 1, Text: cut(lines[h])})
	}
	sr.out.WriteString("\n")
	return true
}

// cut shortens a long line for the output.
func cut(l string) string {
	if len(l) <= maxLineShown {
		return l
	}
	i := maxLineShown
	for i > 0 && !utf8.RuneStart(l[i]) {
		i--
	}
	return l[:i] + " …"
}
