package e2e

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A call that a permission marks for review (obligation "review")
// becomes a review item once it ran, under the real policy; one without
// the mark does not. Its approver (here the principal, by the default
// rule "self") lists it and gives verdicts; an incident needs a reason,
// a later verdict replaces the first, and both are audited.
func TestReviews(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	home, err := os.MkdirTemp("", "mcpgw-review")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	writeFile(t, filepath.Join(home, "hello.txt"), "hello")
	rbac := fmt.Sprintf(`{
	  "roles": {"bot": {"permissions": [
	    {"server": "fs", "tool": "read_text_file", "obligations": {"review": true, "audit": "full"}},
	    {"server": "fs", "tool": "read_file"}
	  ]}},
	  "bindings": {"groups": {}, "users": {%q: ["bot"]}}
	}`, me.Username)
	e := setup(t, rbac, map[string]string{"fs": home}, "")
	defer func() {
		if t.Failed() {
			t.Logf("gateway:\n%s", e.gwLogs.String())
		}
	}()
	c := newClient(t, e.connect, e.gwSock, "fs")
	c.initialize(map[string]any{})
	path := filepath.Join(home, "hello.txt")
	if text, isErr := toolResult(t, c.call(2, "read_file", map[string]any{"path": path})); isErr || text != "hello" {
		t.Fatalf("read_file: %q", text)
	}
	if text, isErr := toolResult(t, c.call(3, "read_text_file", map[string]any{"path": path})); isErr || text != "hello" {
		t.Fatalf("read_text_file: %q", text)
	}

	ctl := controlClient(e.ctlSock)
	var items []map[string]any
	controlDo(t, ctl, "GET", "/v1/reviews", "", &items)
	if len(items) != 1 || items[0]["name"] != "read_text_file" || items[0]["outcome"] != "ok" || items[0]["decision_id"] == "" {
		t.Fatalf("review items %v", items)
	}
	args, _ := items[0]["args"].(map[string]any)
	if args["path"] != path {
		t.Fatalf("arguments (audit full) %v", items[0]["args"])
	}
	id, _ := items[0]["id"].(string)

	if code := controlDo(t, ctl, "POST", "/v1/reviews/"+id, `{"verdict": "incident"}`, nil); code != 400 {
		t.Fatalf("incident without a reason: %d", code)
	}
	if code := controlDo(t, ctl, "POST", "/v1/reviews/"+id, `{"verdict": "incident", "reason": "read the wrong file", "via": "cli"}`, nil); code != 200 {
		t.Fatalf("incident: %d", code)
	}
	var got map[string]any
	if code := controlDo(t, ctl, "POST", "/v1/reviews/"+id, `{"verdict": "ok"}`, &got); code != 200 {
		t.Fatalf("ok: %d", code)
	}
	if v, _ := got["verdict"].(map[string]any); v["verdict"] != "ok" || v["by"] != me.Username {
		t.Fatalf("after the second verdict %v", got)
	}
	audited := 0
	for i := 0; i < 100 && audited < 2; i++ {
		audited = 0
		for _, line := range strings.Split(e.gwLogs.String(), "\n") {
			if strings.Contains(line, `"event":"mcp-review"`) && strings.Contains(line, `"id":"`+id+`"`) {
				audited++
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if audited != 2 {
		t.Fatalf("%d verdicts audited, want 2", audited)
	}
}
