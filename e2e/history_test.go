package e2e

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"
)

// The clients' history on the control socket: a client that came and
// went is listed with its tool calls and how it ended, kept across a
// restart of the gateway.
func TestClientHistory(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	home, err := os.MkdirTemp("", "mcpgw-history")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	writeFile(t, filepath.Join(home, "hello.txt"), "hello")
	rbac := fmt.Sprintf(`{"roles": {"reader": {"permissions": [{"server": "fs", "tool": "read_*"}]}},
	  "bindings": {"groups": {}, "users": {%q: ["reader"]}}}`, me.Username)
	e := setup(t, rbac, map[string]string{"fs": home}, "")
	c := newClient(t, e.connect, e.gwSock, "fs")
	c.initialize(map[string]any{})
	for i := range 2 {
		if text, isErr := toolResult(t, c.call(10+i, "read_file", map[string]any{"path": filepath.Join(home, "hello.txt")})); isErr || text != "hello" {
			t.Fatalf("read: %q", text)
		}
	}
	_ = c.stdin.Close() // mcp-connect ends, and the session with it

	ctl := controlClient(e.ctlSock)
	find := func() map[string]any {
		var list []map[string]any
		controlDo(t, ctl, "GET", "/v1/sessions/history", "", &list)
		for _, rec := range list {
			if rec["sub"] == me.Username && rec["ended"] != nil {
				return rec
			}
		}
		return nil
	}
	var rec map[string]any
	for i := 0; i < 250 && rec == nil; i++ {
		rec = find()
		time.Sleep(20 * time.Millisecond)
	}
	if rec == nil || rec["end"] != "disconnected" || rec["calls"] != float64(2) || rec["endpoint"] != "fs" {
		t.Fatalf("history %v\n%s", rec, e.gwLogs.String())
	}
	e.restartGateway(t)
	if again := find(); again == nil || again["id"] != rec["id"] || again["calls"] != float64(2) {
		t.Fatalf("after a restart %v", again)
	}
}
