package router

import (
	"path/filepath"
	"testing"
	"time"
)

// waitHistory waits for a record of sub with an end (ended) or without.
func waitHistory(t *testing.T, r *Router, sub string, ended bool) ClientRecord {
	t.Helper()
	for i := 0; i < 400; i++ {
		for _, c := range r.History(time.Time{}, time.Time{}) {
			if c.Sub == sub && (c.Ended != nil) == ended {
				return c
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no record of %s (ended %v): %+v", sub, ended, r.History(time.Time{}, time.Time{}))
	return ClientRecord{}
}

// A session is in the history from its initialize: while connected, then
// with its end, the tool calls the gateway forwarded for it and how it
// ended; also across a restart.
func TestHistorySessions(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	r.HistoryFile = filepath.Join(t.TempDir(), "clients.json")
	p := alice()
	c := connect(t, r, p, "fs", nil)
	c.roundTrip(1, "tools/call", map[string]any{"name": "read_file"})
	c.roundTrip(2, "tools/call", map[string]any{"name": "read_file"})
	c.roundTrip(3, "tools/list", map[string]any{})
	live := waitHistory(t, r, "alice", false)
	if live.ID != p.SessionID || live.Kind != "session" || live.Endpoint != "fs" || live.Client.Name != "test" || live.Calls != 2 ||
		live.Protocol == "" || live.LastActive.Before(live.Started) {
		t.Fatalf("live record %+v", live)
	}
	c.close()
	ended := waitHistory(t, r, "alice", true)
	if ended.End != EndDisconnected || ended.Calls != 2 || ended.Ended.Before(ended.Started) {
		t.Fatalf("ended record %+v", ended)
	}

	// Ended by an administrator.
	q := alice()
	q.Sub = "bob"
	connect(t, r, q, "fs", nil)
	if err := r.EndSession(q.SessionID, "root (control API)"); err != nil {
		t.Fatal(err)
	}
	if rec := waitHistory(t, r, "bob", true); rec.End != EndEnded || rec.EndedBy != "root (control API)" {
		t.Fatalf("ended by an administrator %+v", rec)
	}

	// A client still open when the gateway stopped ended then, in the
	// history the next start reads.
	o := alice()
	o.Sub = "olga"
	connect(t, r, o, "fs", nil)
	waitHistory(t, r, "olga", false)
	next, _ := testRouter(t, time.Hour)
	next.HistoryFile = r.HistoryFile
	all := next.History(time.Time{}, time.Time{})
	if len(all) != 3 {
		t.Fatalf("restored %+v", all)
	}
	for _, rec := range all {
		if rec.Sub == "olga" && rec.End != EndRestart {
			t.Fatalf("open at the restart %+v", rec)
		}
		if rec.Sub == "alice" && (rec.End != EndDisconnected || rec.Calls != 2) {
			t.Fatalf("restored %+v", rec)
		}
	}
}

// The time frame: clients connected at some time in it.
func TestHistoryWindow(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	c := connect(t, r, alice(), "fs", nil)
	c.close()
	rec := waitHistory(t, r, "alice", true)
	for name, tc := range map[string]struct {
		since, until time.Time
		want         int
	}{
		"around it":        {rec.Started.Add(-time.Minute), rec.Ended.Add(time.Minute), 1},
		"overlapping end":  {rec.Started.Add(time.Nanosecond), time.Time{}, 1},
		"before it began":  {time.Time{}, rec.Started.Add(-time.Second), 0},
		"after it ended":   {rec.Ended.Add(time.Second), time.Time{}, 0},
		"no bounds at all": {time.Time{}, time.Time{}, 1},
	} {
		if got := r.History(tc.since, tc.until); len(got) != tc.want {
			t.Errorf("%s: %d records", name, len(got))
		}
	}
}

// Ended clients older than the retention go; connected ones stay.
func TestHistoryRetention(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	r.HistoryRetention = time.Millisecond
	c := connect(t, r, alice(), "fs", nil)
	c.close()
	waitHistory(t, r, "alice", true)
	time.Sleep(5 * time.Millisecond)
	q := alice()
	q.Sub = "bob"
	connect(t, r, q, "fs", nil) // writing the history prunes it
	got := r.History(time.Time{}, time.Time{})
	if len(got) != 1 || got[0].Sub != "bob" {
		t.Fatalf("after the retention %+v", got)
	}
}

// An agent of 2026-07-28 is in the history from its first request until
// it is no longer seen; when it comes back, it is a new record.
func TestHistoryAgents(t *testing.T) {
	r, _ := testRouter(t, time.Hour)
	c := agent(t, r, alice(), "fs")
	c.roundTrip(1, "tools/call", withAgentMeta(map[string]any{"name": "read_file"}, nil))
	c.roundTrip(2, "tools/call", withAgentMeta(map[string]any{"name": "read_file"}, nil))
	rec := waitHistory(t, r, "alice", false)
	if rec.Kind != "agent" || rec.Calls != 2 || rec.Protocol != modernVersion {
		t.Fatalf("agent record %+v", rec)
	}
	var clientID string
	for _, s := range r.Sessions() {
		if s.Kind == "agent" {
			clientID = s.ID
		}
	}
	if clientID == "" || rec.ID == clientID || rec.ID[:len(clientID)] != clientID {
		t.Fatalf("record id %q for client %q", rec.ID, clientID)
	}
	// Its request is let go just after the answer: idle, then not seen.
	for i := 0; i < 400; i++ {
		idle := true
		for _, s := range r.Sessions() {
			if s.ID == clientID && (s.Requests > 0 || s.Streams > 0) {
				idle = false
			}
		}
		if idle {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.agentMu.Lock()
	r.pruneAgentClients(time.Now().Add(2 * agentSeenFor))
	r.agentMu.Unlock()
	ended := waitHistory(t, r, "alice", true)
	if ended.End != EndNotSeen || ended.Calls != 2 || ended.Ended.After(time.Now()) {
		t.Fatalf("not seen %+v", ended)
	}
	c.roundTrip(3, "tools/call", withAgentMeta(map[string]any{"name": "read_file"}, nil))
	back := waitHistory(t, r, "alice", false)
	if back.ID == ended.ID || back.Calls != 1 {
		t.Fatalf("back %+v (before %s)", back, ended.ID)
	}
}
