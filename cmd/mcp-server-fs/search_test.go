package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// search_text finds lines by text or regular expression, case-insensitive
// by default, with context merged across nearby matches, below a
// directory or in one file.
func TestSearchText(t *testing.T) {
	s, root := newTestServer(t, 1)
	write(t, filepath.Join(root, "guide", "a.md"), "one\ntwo\nThe Gateway\nthree\nfour\nfive\nsix\nseven\ngateway again\neight\n")
	write(t, filepath.Join(root, "b.md"), "nothing here\n")
	write(t, filepath.Join(root, "bin.dat"), "gateway\x00\x01")

	r := call(t, s, "search_text", map[string]any{"path": ".", "query": "gateway"})
	got := mustOK(t, r)
	want := filepath.Join(root, "guide", "a.md") + "\n1- one\n2- two\n3: The Gateway\n4- three\n5- four\n--\n7- six\n8- seven\n9: gateway again\n10- eight"
	if got != want {
		t.Errorf("default search:\n%s\nwant:\n%s", got, want)
	}
	if m := r.Structured["matches"].([]any); len(m) != 2 || m[0].(map[string]any)["line"].(float64) != 3 || r.Structured["truncated"] != false {
		t.Errorf("structured: %v", r.Structured)
	}

	// Case, regular expressions, no context, one file.
	if got := mustOK(t, call(t, s, "search_text", map[string]any{"path": ".", "query": "Gateway", "caseSensitive": true, "context": 0})); !strings.HasSuffix(got, "\n3: The Gateway") {
		t.Errorf("case-sensitive: %q", got)
	}
	if got := mustOK(t, call(t, s, "search_text", map[string]any{"path": "guide/a.md", "query": `^e\w+t$`, "regexp": true, "context": 0})); !strings.HasSuffix(got, "\n10: eight") {
		t.Errorf("regexp in one file: %q", got)
	}
	if got := mustOK(t, call(t, s, "search_text", map[string]any{"path": ".", "query": "absent"})); got != "no matches" {
		t.Errorf("no matches: %q", got)
	}
	mustFail(t, call(t, s, "search_text", map[string]any{"path": ".", "query": "(", "regexp": true}), "not a valid regular expression")
	mustFail(t, call(t, s, "search_text", map[string]any{"path": ".", "query": ""}), "query")
	mustFail(t, call(t, s, "search_text", map[string]any{"path": ".", "query": "x", "context": 11}), "context")

	// Excluded paths.
	if got := mustOK(t, call(t, s, "search_text", map[string]any{"path": ".", "query": "gateway", "excludePatterns": []string{"guide"}})); got != "no matches" {
		t.Errorf("excluded: %q", got)
	}

	// Capped by maxResults.
	r = call(t, s, "search_text", map[string]any{"path": ".", "query": "gateway", "maxResults": 1, "context": 0})
	if got := mustOK(t, r); !strings.Contains(got, "3: The Gateway") || strings.Contains(got, "again") ||
		!strings.Contains(got, "stopped after 1") || r.Structured["truncated"] != true {
		t.Errorf("capped: %q %v", got, r.Structured)
	}
}

// Context at the edges of a file, long lines cut, links not followed,
// and nothing outside the roots.
func TestSearchTextEdges(t *testing.T) {
	s, root := newTestServer(t, 1)
	outside := t.TempDir()
	write(t, filepath.Join(outside, "secret"), "gateway\n")
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "edge"), "gateway first\nmiddle\ngateway last")
	write(t, filepath.Join(root, "long"), strings.Repeat("ä", 300)+" gateway\n")

	got := mustOK(t, call(t, s, "search_text", map[string]any{"path": ".", "query": "gateway", "context": 5}))
	if strings.Contains(got, "secret") || strings.Contains(got, outside) {
		t.Errorf("followed a link out of the root: %s", got)
	}
	if !strings.Contains(got, "1: gateway first\n2- middle\n3: gateway last") {
		t.Errorf("edges: %s", got)
	}
	if !regexp.MustCompile(`1: ä+ …`).MatchString(got) {
		t.Errorf("long line not cut: %s", got)
	}
	mustFail(t, call(t, s, "search_text", map[string]any{"path": "link", "query": "gateway"}), "")
	mustFail(t, call(t, s, "search_text", map[string]any{"path": "../", "query": "gateway"}), "")
}

// read_text_file reads a range of lines and says which.
func TestReadTextRange(t *testing.T) {
	s, root := newTestServer(t, 1)
	write(t, filepath.Join(root, "lines"), "1\n2\n3\n4\n5\n")
	write(t, filepath.Join(root, "nonl"), "a\nb\nc")
	for _, tc := range []struct {
		args map[string]any
		want string
	}{
		{map[string]any{"path": "lines", "offset": 2, "limit": 2}, "2\n3\n[lines 2-3 of 5]"},
		{map[string]any{"path": "lines", "offset": 4}, "4\n5\n[lines 4-5 of 5]"},
		{map[string]any{"path": "lines", "limit": 1}, "1\n[lines 1-1 of 5]"},
		{map[string]any{"path": "lines", "offset": 5, "limit": 9}, "5\n[lines 5-5 of 5]"},
		{map[string]any{"path": "nonl", "offset": 3}, "c\n[lines 3-3 of 3]"},
	} {
		if got := mustOK(t, call(t, s, "read_text_file", tc.args)); got != tc.want {
			t.Errorf("%v: %q, want %q", tc.args, got, tc.want)
		}
	}
	mustFail(t, call(t, s, "read_text_file", map[string]any{"path": "lines", "offset": 6}), "past its end")
	mustFail(t, call(t, s, "read_text_file", map[string]any{"path": "lines", "offset": 1, "head": 1}), "one of head, tail")
	s.maxRead = 3
	mustFail(t, call(t, s, "read_text_file", map[string]any{"path": "lines", "offset": 1}), "smaller limit")
	if got := mustOK(t, call(t, s, "read_text_file", map[string]any{"path": "lines", "offset": 2, "limit": 1})); got != "2\n[lines 2-2 of 5]" {
		t.Errorf("range under the limit: %q", got)
	}
}

// The gateway-docs server's instructions name only tools this server has,
// and tell agents to search before reading.
func TestGatewayDocsInstructions(t *testing.T) {
	for file, wants := range map[string][]string{
		"gateway-docs.yaml.in": {"search_text", "offset", "limit"},
		"fs.yaml.in":           {"gateway-admin", "show_config"},
	} {
		b, err := os.ReadFile("../../packaging/fs-server/" + file)
		if err != nil {
			t.Fatal(err)
		}
		m := regexp.MustCompile(`"--instructions", "((?:[^"\\]|\\.)*)"`).FindSubmatch(b)
		if m == nil {
			t.Fatalf("no --instructions in %s", file)
		}
		instr := string(m[1])
		s, _ := newTestServer(t, 1)
		have := map[string]bool{}
		for _, tl := range s.tools() {
			have[tl.name] = true
		}
		// Tool-like names: lower-case words joined by underscores, as the
		// server's tools are named. show_config, check_config and doctor are
		// the gateway-admin server's, named as such.
		other := map[string]bool{"show_config": true, "check_config": true}
		for _, name := range regexp.MustCompile(`\b[a-z]+(?:_[a-z]+)+\b`).FindAllString(instr, -1) {
			if !have[name] && !other[name] {
				t.Errorf("%s: the instructions name %q, which mcp-server-fs does not have", file, name)
			}
		}
		for _, want := range wants {
			if !strings.Contains(instr, want) {
				t.Errorf("%s: the instructions do not mention %s", file, want)
			}
		}
	}
}
