package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// An agent looks something up in the gateway's documentation as the
// gateway-docs instructions say (roadmap step 27): search_text finds the
// line, read_text_file reads the lines around it, and neither returns
// more than a small part of the file.
func TestDocsLookup(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	docs, err := filepath.Abs(filepath.Join("..", "docs"))
	if err != nil {
		t.Fatal(err)
	}
	rbac := fmt.Sprintf(`{
	  "roles": {"reader": {"permissions": [
	    {"server": "docs", "tool": "search_text"},
	    {"server": "docs", "tool": "read_*"}
	  ]}},
	  "bindings": {"groups": {}, "users": {%q: ["reader"]}}
	}`, me.Username)
	e := setup(t, rbac, map[string]string{"docs": docs}, "")
	c := newClient(t, e.connect, e.gwSock, "docs")
	c.initialize(map[string]any{})

	m := c.call(2, "search_text", map[string]any{"path": ".", "query": "agents.no_request_timeout", "maxResults": 5})
	text, isErr := toolResult(t, m)
	var res struct {
		Structured struct {
			Matches []struct {
				Path string
				Line int
			}
			Truncated bool
		} `json:"structuredContent"`
	}
	if err := json.Unmarshal(m.Result, &res); err != nil || isErr || len(res.Structured.Matches) == 0 {
		t.Fatalf("search_text: %v %q %s", isErr, text, m.Result)
	}
	if len(text) > 4096 {
		t.Errorf("search_text returned %d bytes for 5 matches", len(text))
	}

	hit := res.Structured.Matches[0]
	m = c.call(3, "read_text_file", map[string]any{"path": hit.Path, "offset": max(hit.Line-5, 1), "limit": 20})
	text, isErr = toolResult(t, m)
	whole, err := os.Stat(hit.Path)
	if err != nil {
		t.Fatal(err)
	}
	if isErr || !strings.Contains(text, "no_request_timeout") || !strings.Contains(text, "[lines ") ||
		int64(len(text)) >= whole.Size() {
		t.Fatalf("read_text_file around line %d of %s: %v %q", hit.Line, hit.Path, isErr, text)
	}
}
