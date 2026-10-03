package router

import (
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

func TestSetBackends(t *testing.T) {
	r, l := testRouter(t, 0)
	agg := connect(t, r, alice(), "", nil)
	single := connect(t, r, alice(), "git", nil)
	tmp := connect(t, r, alice(), "tmp", nil)
	for i, c := range []*client{agg, single, tmp} {
		c.roundTrip(1, "tools/list", map[string]any{})
		if i > 0 {
			c.roundTrip(2, "tools/call", map[string]any{"name": "read_file"})
		}
	}
	agg.roundTrip(2, "tools/call", map[string]any{"name": "fs__read_file"})
	fs, git := l.started("fs")[0], l.started("git")[0]
	tmpInst := l.started("tmp")[0]

	// Unchanged definitions change nothing.
	if ch := r.SetBackends(r.CurrentBackends()); !ch.Empty() {
		t.Fatalf("changes %+v", ch)
	}

	// git changes, tmp goes, web comes.
	ch := r.SetBackends(map[string]*config.Backend{
		"fs":  {Name: "fs", Isolation: config.IsolationPrincipal},
		"git": {Name: "git", Isolation: config.IsolationPrincipal, Network: true},
		"web": {Name: "web", Isolation: config.IsolationPrincipal},
	})
	if strings.Join(ch.Added, ",") != "web" || strings.Join(ch.Changed, ",") != "git" || strings.Join(ch.Removed, ",") != "tmp" {
		t.Fatalf("changes %+v", ch)
	}
	for _, c := range []*client{agg, single, tmp} {
		if m := c.read(); m.Method != "notifications/tools/list_changed" {
			t.Fatalf("got %+v", m)
		}
		c.read()
		c.read()
	}

	// The removed server's instance stops now.
	if !isClosed(tmpInst.closed, 5*time.Second) {
		t.Fatal("instance of the removed server still runs")
	}
	if m := tmp.roundTrip(3, "tools/call", map[string]any{"name": "read_file"}); m.Error == nil {
		t.Fatalf("call to a removed server: %+v", m)
	}

	// The aggregated session lists the new set.
	got := names(t, agg.roundTrip(3, "tools/list", map[string]any{}), "tools", "name")
	if s := strings.Join(got, ","); strings.Contains(s, "tmp__") || !strings.Contains(s, "web__read_file") || !strings.Contains(s, "git__read_file") {
		t.Fatalf("tools = %v", got)
	}

	// The unchanged server keeps its instance.
	agg.roundTrip(4, "tools/call", map[string]any{"name": "fs__read_file"})
	if n := len(l.started("fs")); n != 1 {
		t.Fatalf("fs started %d times", n)
	}
	if isClosed(fs.closed, 50*time.Millisecond) {
		t.Fatal("instance of an unchanged server stopped")
	}
	// The changed server's instance runs until the session's next call,
	// which starts an instance from the new definition.
	if isClosed(git.closed, 50*time.Millisecond) {
		t.Fatal("instance of the changed server stopped before the session's next call")
	}
	if text, _ := toolText(t, single.roundTrip(4, "tools/call", map[string]any{"name": "read_file"})); text != "git did read_file" {
		t.Fatalf("got %q", text)
	}
	if n := len(l.started("git")); n != 2 {
		t.Fatalf("git started %d times", n)
	}
	if !isClosed(git.closed, 5*time.Second) {
		t.Fatal("old instance of the changed server still runs after the session moved")
	}
	if text, _ := toolText(t, single.roundTrip(5, "tools/call", map[string]any{"name": "read_file"})); text != "git did read_file" ||
		len(l.started("git")) != 2 {
		t.Fatalf("got %q, %d starts", text, len(l.started("git")))
	}

	// New sessions see the new set.
	web := connect(t, r, alice(), "web", nil)
	if text, _ := toolText(t, web.roundTrip(1, "tools/call", map[string]any{"name": "read_file"})); text != "web did read_file" {
		t.Fatalf("got %q", text)
	}
}
