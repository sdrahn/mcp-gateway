package router

import (
	"strings"
	"testing"
)

func TestExcerpt(t *testing.T) {
	if got := excerpt([]byte("usage: suseconnect-mcp [flags]"), 200); got != "usage: suseconnect-mcp [flags]" {
		t.Errorf("short line: %q", got)
	}
	long := strings.Repeat("x", 250)
	if got := excerpt([]byte(long), 200); got != strings.Repeat("x", 200)+"…" {
		t.Errorf("long line: %d bytes", len(got))
	}
	// Cut inside a multi-byte character, and invalid UTF-8 from the backend.
	if got := excerpt([]byte("ab\xc3\xa4"), 3); got != "ab�…" {
		t.Errorf("cut rune: %q", got)
	}
	if got := excerpt([]byte("a\xffb"), 200); got != "a�b" {
		t.Errorf("invalid UTF-8: %q", got)
	}
}
