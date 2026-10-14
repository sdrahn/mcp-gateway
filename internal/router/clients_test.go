package router

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/config"
)

// The clients: a session with its client, the version it asked for and
// got and the cap that lowered it, and its instances; a modern agent as
// last seen, with its open stream; a connection of modern requests only
// is no session.
func TestSessions(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	r.SetSettings(Settings{MaxVersion: map[string]string{"test": "2025-06-18"}})
	c := connectVersion(t, r, alice(), "fs", map[string]any{}, nil, "2025-11-25")
	a := agent(t, r, bob(), "")
	listenAck(t, a, 1, map[string]any{"toolsListChanged": true})

	var session, modern SessionInfo
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := r.Sessions()
		if len(got) == 2 {
			session, modern = got[0], got[1]
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sessions %+v", got)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if session.Kind != "session" || session.Sub != "alice" || session.ID == "" || session.Endpoint != "fs" || session.Client.Name != "test" ||
		session.Requested != "2025-11-25" || session.Protocol != "2025-06-18" || session.Capped != "2025-06-18" ||
		len(session.Instances) != 1 || session.LastActive.Before(session.Started) {
		t.Fatalf("session %+v", session)
	}
	if modern.Kind != "agent" || modern.Sub != "bob" || modern.Endpoint != "all" || len(modern.Servers) == 0 ||
		modern.Client.Name != "modern-agent" || modern.Client.Version != "1" || modern.Protocol != modernVersion ||
		modern.Streams != 1 || modern.Requests != 0 {
		t.Fatalf("agent %+v", modern)
	}
	// The agent's next request is the same client; one that names
	// another is another.
	if m := a.roundTrip(2, "tools/list", withAgentMeta(nil, nil)); m.Error != nil {
		t.Fatal(m.Error)
	}
	other := map[string]any{metaClientInfo: map[string]any{"name": "modern-agent", "version": "2"}}
	if m := a.roundTrip(3, "tools/list", withAgentMeta(nil, other)); m.Error != nil {
		t.Fatal(m.Error)
	}
	if got := r.Sessions(); len(got) != 3 || got[1].ID != modern.ID || !got[1].LastActive.After(modern.LastActive) ||
		got[2].Client.Version != "2" || got[2].ID == modern.ID {
		t.Fatalf("after more requests: %+v", got)
	}

	// An ended session is gone.
	c.close()
	deadline = time.Now().Add(2 * time.Second)
	for len(r.Sessions()) != 2 {
		if time.Now().After(deadline) {
			t.Fatalf("an ended session is listed: %+v", r.Sessions())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Agents are listed for an hour after their last request, at most
// limits.sessions_per_principal per principal; one with a request in
// flight stays.
func TestAgentClientsPruned(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	r.SetSettings(Settings{MaxSessionsPerPrincipal: 2})
	now := time.Now()
	r.agents.clients = map[string]*agentClient{
		"old":  {id: "old", principal: alice(), last: now.Add(-2 * agentSeenFor)},
		"busy": {id: "busy", principal: alice(), last: now.Add(-2 * agentSeenFor), requests: 1},
		"a1":   {id: "a1", principal: alice(), last: now.Add(-3 * time.Minute)},
		"a2":   {id: "a2", principal: alice(), last: now.Add(-2 * time.Minute)},
		"b1":   {id: "b1", principal: bob(), last: now.Add(-time.Minute)},
	}
	r.agentMu.Lock()
	r.pruneAgentClients(now)
	r.agentMu.Unlock()
	var ids []string
	for k := range r.agents.clients {
		ids = append(ids, k)
	}
	if len(ids) != 3 || r.agents.clients["busy"] == nil || r.agents.clients["a2"] == nil || r.agents.clients["b1"] == nil {
		t.Fatalf("kept %v", ids)
	}
}

// busy waits until an instance of server has a call in flight.
func waitBusy(t *testing.T, r *Router, server string) {
	t.Helper()
	waitFor(t, func() bool {
		for _, in := range r.Instances() {
			if in.Server == server && in.Busy {
				return true
			}
		}
		return false
	})
}

// sessionOf returns the id of sub's listed client of kind.
func sessionOf(t *testing.T, r *Router, sub, kind string) string {
	t.Helper()
	for _, c := range r.Sessions() {
		if c.Sub == sub && c.Kind == kind {
			return c.ID
		}
	}
	t.Fatalf("no %s of %s in %+v", kind, sub, r.Sessions())
	return ""
}

// Ending a session is as if its client had gone: its call is cancelled
// at the server, the connection closes, and it is audited; a privileged
// server's instance runs until its call ends.
func TestEndSession(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	var logs strings.Builder
	r.Audit = audit.New(&syncWriter{w: &logs})

	c := connect(t, r, alice(), "fs", nil)
	c.send(1, "tools/call", map[string]any{"name": "slow"})
	waitBusy(t, r, "fs")
	id := sessionOf(t, r, "alice", "session")
	if err := r.EndSession(id, "root (control API)"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-l.started("fs")[0].cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("the call was not cancelled at the server")
	}
	if !isClosed(c.done, 2*time.Second) {
		t.Fatal("the session did not end")
	}
	if got := r.Sessions(); len(got) != 0 {
		t.Fatalf("an ended session is listed: %+v", got)
	}
	if err := r.EndSession(id, "root"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("ending it again: %v", err)
	}
	if !strings.Contains(logs.String(), `"event":"mcp-session-ended"`) || !strings.Contains(logs.String(), `"by":"root (control API)"`) ||
		!strings.Contains(logs.String(), `"client":"test"`) || !strings.Contains(logs.String(), `"session":"`+id+`","transport":"unix"`) {
		t.Fatalf("audit: %s", logs.String())
	}

	// Without an idle timeout, so that only the call keeps the instance.
	r, l = testRouter(t, 0)
	r.Backends["zypp"] = &config.Backend{Name: "zypp", Isolation: config.IsolationPrincipal, Privileged: true}
	z := connect(t, r, alice(), "zypp", nil)
	z.send(1, "tools/call", map[string]any{"name": "commit"})
	waitBusy(t, r, "zypp")
	if err := r.EndSession(sessionOf(t, r, "alice", "session"), "root"); err != nil {
		t.Fatal(err)
	}
	if !isClosed(z.done, 2*time.Second) {
		t.Fatal("the privileged session did not end")
	}
	inst := l.started("zypp")[0]
	if isClosed(inst.closed, 100*time.Millisecond) {
		t.Fatal("the privileged instance was stopped during its call")
	}
	close(inst.commit)
	if !isClosed(inst.closed, 2*time.Second) {
		t.Fatal("the privileged instance did not stop after its call")
	}
}

// Ending a modern agent ends its stream and its request in flight, which
// are answered with an error; its next request is served.
func TestEndAgent(t *testing.T) {
	r, l := testRouter(t, time.Hour)
	a := agent(t, r, alice(), "fs")
	listenAck(t, a, 1, map[string]any{"toolsListChanged": true})
	a.send(2, "tools/call", withAgentMeta(map[string]any{"name": "slow"}, nil))
	waitBusy(t, r, "fs")
	if err := r.EndSession(sessionOf(t, r, "alice", "agent"), "root"); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for range 2 {
		m := a.read()
		if m.Error == nil || !strings.Contains(m.Error.Message, "ended by an administrator") {
			t.Fatalf("want an error, got %+v", m)
		}
		got[m.Key()] = true
	}
	if !got["1"] || !got["2"] {
		t.Fatalf("answered %v", got)
	}
	select {
	case <-l.started("fs")[0].cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("the call was not cancelled at the server")
	}
	if m := a.roundTrip(3, "tools/list", withAgentMeta(nil, nil)); m.Error != nil {
		t.Fatalf("the next request: %+v", m.Error)
	}
}
