package e2e

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestPseudonymization runs the obligations "pseudonymize" and
// "reidentify" through the shipped policy: results reach the agent with
// pseudonyms, and a write names the pseudonym but stores the real value.
func TestPseudonymization(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	home, err := os.MkdirTemp("", "mcpgw-home")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	writeFile(t, filepath.Join(home, "contacts.txt"), "Contact: bob@example.com, IBAN DE89 3704 0044 0532 0130 00")

	rbac := fmt.Sprintf(`{
	  "roles": {"developer": {"permissions": [
	    {"server": "fs", "tool": "*", "obligations": {"pseudonymize": {"detect": ["email", "iban"]}}},
	    {"server": "fs", "tool": "read_*"},
	    {"server": "fs", "tool": "write_file", "args": {"path": %q}, "obligations": {"reidentify": ["content"]}}
	  ]}},
	  "bindings": {"groups": {}, "users": {%q: ["developer"]}}
	}`, "^"+regexp.QuoteMeta(home)+"/", me.Username)
	e := setup(t, rbac, map[string]string{"fs": home}, "")
	c := newClient(t, e.connect, e.gwSock, "fs")
	c.request(1, "initialize", map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "e2e", "version": "1"},
	})
	if m := c.read(); m.Error != nil {
		t.Fatalf("initialize: %+v", m)
	}
	c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})

	text, isErr := toolResult(t, c.call(2, "read_file", map[string]any{"path": filepath.Join(home, "contacts.txt")}))
	if isErr || text != "Contact: [EMAIL_1], IBAN [IBAN_1]" {
		t.Fatalf("read: %q isError=%v", text, isErr)
	}

	out := filepath.Join(home, "reply.txt")
	text, isErr = toolResult(t, c.call(3, "write_file", map[string]any{"path": out, "content": "To: [EMAIL_1]"}))
	if isErr || !strings.HasPrefix(text, "wrote") {
		t.Fatalf("write: %q isError=%v", text, isErr)
	}
	if b, err := os.ReadFile(out); err != nil || string(b) != "To: bob@example.com" {
		t.Fatalf("file content %q, %v", b, err)
	}

	logs := e.gwLogs.String()
	if !strings.Contains(logs, `"event":"mcp-pseudonymize"`) || !strings.Contains(logs, `"reidentified":1`) {
		t.Errorf("audit records missing: %s", logs)
	}
	if strings.Contains(logs, "bob@example.com") {
		t.Error("gateway logs contain the pseudonymized value")
	}
}
