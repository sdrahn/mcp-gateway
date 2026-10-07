package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// outline_file lists the Markdown headings of a file with their line
// numbers and the size of their sections: for a broad question an agent
// reads the outline, then the one section (read_text_file with offset and
// limit) instead of the whole file (docs/architecture.md, roadmap step 28).

var (
	atxHeading  = regexp.MustCompile(`^ {0,3}(#{1,6})(?:[ \t]+(.*?))?[ \t]*$`)
	closingHash = regexp.MustCompile(`(?:^|[ \t]+)#+$`)
	codeFence   = regexp.MustCompile("^ {0,3}(`{3,}|~{3,})")
)

// heading is a heading and the extent of its section, which runs to the
// next heading of the same or a higher level.
type heading struct {
	Level int    `json:"level"`
	Title string `json:"title"`
	Line  int    `json:"line"`
	Lines int    `json:"lines"`
	Bytes int64  `json:"bytes"`
	start int64
}

func outlineTool() tool {
	return tool{name: "outline_file", title: "Outline of a Markdown file",
		description: "The headings of a Markdown file with their line numbers and how many lines and bytes each " +
			"section has (to the next heading of the same or a higher level). Read one section with " +
			"read_text_file (offset: its line, limit: its lines) instead of the whole file. Headings in fenced " +
			"code blocks are not headings.",
		input: obj(map[string]any{"path": pathArg,
			"maxLevel": map[string]any{"type": "integer", "minimum": 1, "maximum": 6,
				"description": "only headings down to this level (default 6: all)"}}, "path"),
		output: obj(map[string]any{
			"headings": map[string]any{"type": "array", "items": obj(map[string]any{
				"level": map[string]any{"type": "integer"}, "title": map[string]any{"type": "string"},
				"line": map[string]any{"type": "integer"}, "lines": map[string]any{"type": "integer"},
				"bytes": map[string]any{"type": "integer"}}, "level", "title", "line", "lines", "bytes")},
			"lines": map[string]any{"type": "integer"}, "bytes": map[string]any{"type": "integer"}},
			"headings", "lines", "bytes"),
		readOnly: true, idempotent: true, run: outlineFile}
}

func outlineFile(s *fileServer, ctx context.Context, args json.RawMessage) (*result, error) {
	a := struct {
		Path     string `json:"path"`
		MaxLevel int    `json:"maxLevel"`
	}{}
	t, err := s.target(args, &a, &a.Path)
	if err != nil {
		return nil, err
	}
	if a.MaxLevel == 0 {
		a.MaxLevel = 6
	}
	if a.MaxLevel < 1 || a.MaxLevel > 6 {
		return nil, errors.New("maxLevel: from 1 to 6")
	}
	root, err := t.dir.open()
	if err != nil {
		return nil, explain(t, err)
	}
	f, err := root.Open(t.rel)
	if err != nil {
		return nil, explain(t, err)
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil {
		return nil, explain(t, err)
	} else if fi.IsDir() {
		return nil, fmt.Errorf("%s: is a directory (search_files finds its Markdown files: \"*.md\")", t.full)
	}

	br := bufio.NewReader(f)
	if sample, _ := br.Peek(8192); isBinary(sample) {
		return nil, fmt.Errorf("%s: not a text file (%s)", t.full, mimeType(t.rel, sample))
	}
	var (
		all    []*heading
		open   []*heading // sections not yet ended, by rising level
		fence  string     // the open code fence, if any
		n      int
		offset int64
	)
	end := func(level int) {
		for len(open) > 0 && open[len(open)-1].Level >= level {
			h := open[len(open)-1]
			h.Lines, h.Bytes = n-h.Line+1, offset-h.start
			open = open[:len(open)-1]
		}
	}
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			if n%4096 == 0 && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			l := strings.TrimRight(line, "\r\n")
			switch m := codeFence.FindStringSubmatch(l); {
			case fence != "":
				if m != nil && m[1][0] == fence[0] && len(m[1]) >= len(fence) &&
					strings.TrimSpace(l[len(m[0]):]) == "" {
					fence = ""
				}
			case m != nil:
				fence = m[1]
			default:
				if h := parseHeading(l); h != nil {
					end(h.Level) // the sections it ends close on the line before
					h.Line, h.start = n+1, offset
					all, open = append(all, h), append(open, h)
				}
			}
			n++
			offset += int64(len(line))
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, explain(t, err)
		}
	}
	end(1)

	shown := []heading{}
	for _, h := range all {
		if h.Level <= a.MaxLevel {
			shown = append(shown, *h)
		}
	}
	var out strings.Builder
	fmt.Fprintf(&out, "%s: %d lines, %s\n", t.full, n, size(offset))
	if len(shown) == 0 {
		out.WriteString("no Markdown headings: read it with read_text_file (head, or offset and limit)")
	} else {
		w := len(strconv.Itoa(shown[len(shown)-1].Line))
		for _, h := range shown {
			fmt.Fprintf(&out, "%*d  %s %s  [%d lines, %s]\n", w, h.Line, strings.Repeat("#", h.Level), h.Title,
				h.Lines, size(h.Bytes))
		}
		out.WriteString("(read a section: read_text_file with offset = its line, limit = its lines)")
	}
	res := text(out.String())
	res.structured = map[string]any{"headings": shown, "lines": n, "bytes": offset}
	return res, nil
}

// parseHeading returns the ATX heading on a line, or nil. Setext headings
// (a line underlined with = or -) are not recognised: a line of dashes is
// as often a rule.
func parseHeading(l string) *heading {
	m := atxHeading.FindStringSubmatch(l)
	if m == nil {
		return nil
	}
	title := strings.TrimSpace(closingHash.ReplaceAllString(m[2], ""))
	if title == "" {
		return nil
	}
	return &heading{Level: len(m[1]), Title: cut(title)}
}
