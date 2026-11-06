package control

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/router"
)

// historySessions is fakeSessions with a history.
type historySessions struct {
	fakeSessions
	records      []router.ClientRecord
	since, until time.Time
}

func (h *historySessions) History(since, until time.Time) []router.ClientRecord {
	h.since, h.until = since, until
	return h.records
}

// The history: the clients the caller may manage (as for those connected
// now), newest first, in the time frame asked for (the last 24 hours by
// default).
func TestSessionHistory(t *testing.T) {
	s, _, _ := setup(t)
	alice, bob := uint32(1001), uint32(1002)
	now := time.Now().UTC().Truncate(time.Second)
	ended := now.Add(-time.Hour)
	h := &historySessions{records: []router.ClientRecord{
		{SessionInfo: router.SessionInfo{ID: "s1", Kind: "session", Sub: "alice", UID: &alice, Endpoint: "fs", Servers: []string{"fs"},
			Started: now.Add(-2 * time.Hour)}, Ended: &ended, End: router.EndDisconnected, Calls: 3},
		{SessionInfo: router.SessionInfo{ID: "s2", Kind: "session", Sub: "bob", UID: &bob, Endpoint: "fs", Servers: []string{"fs"},
			Started: now.Add(-90 * time.Minute)}},
		{SessionInfo: router.SessionInfo{ID: "agent-1-ab", Kind: "agent", Sub: "alice", UID: &alice, Endpoint: "fs", Servers: []string{"fs"},
			Started: now.Add(-time.Minute)}, Calls: 1},
	}}
	s.Sessions = h
	rec := call(t, s, 1001, "GET", "/v1/sessions/history", "")
	var got []router.ClientRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(got) != 2 || got[0].ID != "agent-1-ab" || got[1].ID != "s1" || got[1].Calls != 3 || got[1].End != "disconnected" {
		t.Fatalf("alice's history %+v", got)
	}
	if d := h.until.Sub(h.since); d != 24*time.Hour {
		t.Fatalf("default window %v", d)
	}
	for _, field := range []string{`"ended":"`, `"end":"disconnected"`, `"calls":3`} {
		if !strings.Contains(rec.Body.String(), field) {
			t.Fatalf("no %s in %s", field, rec.Body)
		}
	}
	if rec := call(t, s, 1002, "GET", "/v1/sessions/history", ""); !strings.Contains(rec.Body.String(), `"id":"s2"`) || strings.Contains(rec.Body.String(), "alice") {
		t.Fatalf("bob's history %s", rec.Body)
	}

	since, until := now.Add(-7*24*time.Hour), now.Add(-time.Hour)
	q := url.Values{"since": {since.Format(time.RFC3339)}, "until": {until.Format(time.RFC3339)}}
	if rec := call(t, s, 1001, "GET", "/v1/sessions/history?"+q.Encode(), ""); rec.Code != 200 || !h.since.Equal(since) || !h.until.Equal(until) {
		t.Fatalf("window %d %v %v", rec.Code, h.since, h.until)
	}
	for _, bad := range []string{"since=yesterday", "until=2026-13-01T00:00:00Z",
		"since=" + url.QueryEscape(now.Format(time.RFC3339)) + "&until=" + url.QueryEscape(now.Add(-time.Hour).Format(time.RFC3339))} {
		if rec := call(t, s, 1001, "GET", "/v1/sessions/history?"+bad, ""); rec.Code != 400 {
			t.Errorf("%s: %d %s", bad, rec.Code, rec.Body)
		}
	}
	// A gateway without a history (an older router) lists none.
	s.Sessions = &fakeSessions{}
	if rec := call(t, s, 1001, "GET", "/v1/sessions/history", ""); strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("without a history: %s", rec.Body)
	}
}
