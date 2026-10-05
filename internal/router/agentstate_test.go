package router

import (
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/jsonrpc"
)

// A modern agent's pseudonyms hold across its requests and connections
// on the same endpoint, not on another endpoint or for another
// principal, and go when the vault is idle.
func TestAgentVault(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	call := func(c *client, id int, name string, args map[string]any) (string, bool) {
		return toolText(t, c.roundTrip(id, "tools/call", withAgentMeta(map[string]any{"name": name, "arguments": args}, nil)))
	}
	c := agent(t, r, alice(), "fs")
	if text, isErr := call(c, 1, "read_customer", nil); isErr || !strings.Contains(text, `"id":"[CUSTOMER_1]"`) {
		t.Fatalf("read: %q %v", text, isErr)
	}
	c2 := agent(t, r, alice(), "fs")
	if _, isErr := call(c2, 1, "update_customer", map[string]any{"id": "[CUSTOMER_1]"}); isErr {
		t.Fatal("update refused")
	}
	fs := l.started("fs")[0]
	if got := fs.updateArgs(); got != `{"id":4711}` {
		t.Errorf("another request of the principal: %s", got)
	}

	bob := alice()
	bob.Sub = "bob"
	other := agent(t, r, bob, "fs")
	if _, isErr := call(other, 1, "update_customer", map[string]any{"id": "[CUSTOMER_1]"}); isErr {
		t.Fatal("update refused")
	}
	if got := l.started("fs")[1].updateArgs(); got != `{"id":"[CUSTOMER_1]"}` {
		t.Errorf("another principal's token re-identified: %s", got)
	}
	all := agent(t, r, alice(), "")
	if _, isErr := call(all, 1, "fs__update_customer", map[string]any{"id": "[CUSTOMER_1]"}); isErr {
		t.Fatal("update refused")
	}
	if got := fs.updateArgs(); got != `{"id":"[CUSTOMER_1]"}` {
		t.Errorf("another endpoint's token re-identified: %s", got)
	}

	// Idle: the vault goes.
	r.SetSettings(Settings{VaultIdle: time.Millisecond})
	time.Sleep(5 * time.Millisecond)
	if _, isErr := call(c2, 2, "update_customer", map[string]any{"id": "[CUSTOMER_1]"}); isErr {
		t.Fatal("update refused")
	}
	if got := fs.updateArgs(); got != `{"id":"[CUSTOMER_1]"}` {
		t.Errorf("idle vault kept: %s", got)
	}
}

// A principal's modern requests in flight and subscription streams are
// limited; streams do not count as requests.
func TestAgentLimits(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	r.MaxRequestsPerPrincipal, r.MaxStreamsPerPrincipal = 1, 1
	c := agent(t, r, alice(), "fs")
	listenAck(t, c, 1, map[string]any{"toolsListChanged": true})
	m := c.roundTrip(2, "subscriptions/listen", withAgentMeta(map[string]any{"notifications": map[string]any{}}, nil))
	if m.Error == nil || !strings.Contains(m.Error.Message, "subscription stream limit reached (1)") {
		t.Fatalf("second stream: %+v", m)
	}

	c.send(3, "tools/call", withAgentMeta(map[string]any{"name": "slow"}, nil))
	waitFor(t, func() bool {
		r.agentMu.Lock()
		defer r.agentMu.Unlock()
		return r.agents.requests[principalKey(alice())] == 1
	})
	m = c.roundTrip(4, "tools/list", withAgentMeta(nil, nil))
	if m.Error == nil || !strings.Contains(m.Error.Message, "request limit reached (1)") {
		t.Fatalf("second request: %+v", m)
	}
	bob := alice()
	bob.Sub = "bob"
	if m := agent(t, r, bob, "fs").roundTrip(1, "tools/list", withAgentMeta(nil, nil)); m.Error != nil {
		t.Fatalf("another principal: %+v", m.Error)
	}

	n, _ := jsonrpc.NewNotification("notifications/cancelled", map[string]any{"requestId": 3})
	c.write(n)
	waitFor(t, func() bool {
		r.agentMu.Lock()
		defer r.agentMu.Unlock()
		return r.agents.requests[principalKey(alice())] == 0
	})
	if m := c.roundTrip(6, "tools/list", withAgentMeta(nil, nil)); m.Error != nil {
		t.Fatalf("after the request ended: %+v", m.Error)
	}
}
