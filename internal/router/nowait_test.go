package router

import (
	"strings"
	"testing"
	"time"
)

// The tool error names the call, the approval, until when, and how to get
// it decided, for the model to pass on.
func TestApprovalNeeded(t *testing.T) {
	exp := time.Date(2026, 10, 25, 9, 42, 0, 0, time.UTC)
	got := approvalNeeded("fs", "write_file", "a-0123", exp, "gw1", "")
	for _, want := range []string{
		"approval needed: fs/write_file waits for an approver's decision (approval a-0123, open until 09:42 UTC).",
		`Tell the user: an approver runs "mcp-gateway-admin approvals approve a-0123" on gw1.`,
		"Then call the tool again with the same arguments; it runs once approved.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %q:\n%s", want, got)
		}
	}
	if got := approvalNeeded("fs", "write_file", "a-0123", exp, "gw1", "https://gw1:9090/a/a-0123"); !strings.Contains(got,
		`on gw1, or decides at https://gw1:9090/a/a-0123.`) {
		t.Errorf("without the page:\n%s", got)
	}
}
