package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

// Review items over the control API: listed for who may review them (no
// approver policy: the principal themself, and root), judged, a verdict
// "ok" on one's own call needs the password, an incident a reason.
func TestReviewsAPI(t *testing.T) {
	s := noticeServer(t)
	passwords := 0
	s.OwnPassword = func(_ context.Context, _ transport.PeerCred, p broker.Pending) error {
		passwords++
		if p.Server != "systemd" || p.Name != "restart_unit" {
			t.Errorf("password asked for %+v", p)
		}
		return errors.New("no polkit agent")
	}
	uid := uint32(1001)
	item := s.Broker.AddReview(broker.Review{Principal: principal.Principal{Sub: "alice", UID: &uid}, Action: "tools.call",
		Server: "systemd", Name: "restart_unit", DecisionID: "d-1", Outcome: "ok"})

	var list []broker.Review
	if rec := as(t, s, 1001, "GET", "/v1/reviews", ""); rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &list) != nil ||
		len(list) != 1 || list[0].ID != item.ID {
		t.Fatalf("alice's reviews: %s", rec.Body)
	}
	if rec := as(t, s, 1002, "GET", "/v1/reviews", ""); strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("bob's reviews: %s", rec.Body)
	}
	if rec := as(t, s, 1002, "GET", "/v1/reviews/"+item.ID, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("bob got the item: %d", rec.Code)
	}

	// Her own call, reviewable by "self" only: "ok" needs her password.
	rec := as(t, s, 1001, "POST", "/v1/reviews/"+item.ID, `{"verdict": "ok"}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":"password_required"`) || passwords != 1 {
		t.Fatalf("own ok without a password: %d %s", rec.Code, rec.Body)
	}
	if rec := as(t, s, 1001, "POST", "/v1/reviews/"+item.ID, `{"verdict": "incident"}`); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "needs a reason") {
		t.Fatalf("incident without a reason: %d %s", rec.Code, rec.Body)
	}
	if rec := as(t, s, 1001, "POST", "/v1/reviews/"+item.ID, `{"verdict": "incident", "reason": "wrong unit"}`); rec.Code != http.StatusOK || passwords != 1 {
		t.Fatalf("own incident: %d %s", rec.Code, rec.Body)
	}
	// Root replaces the verdict.
	var got broker.Review
	rec = as(t, s, 0, "POST", "/v1/reviews/"+item.ID, `{"verdict": "ok", "via": "cli"}`)
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Verdict == nil ||
		got.Verdict.Verdict != "ok" || got.Verdict.By != "root" || got.Verdict.Via != "cli" {
		t.Fatalf("root's verdict: %d %s", rec.Code, rec.Body)
	}
	if rec := as(t, s, 1002, "POST", "/v1/reviews/"+item.ID, `{"verdict": "ok"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("bob judged: %d", rec.Code)
	}
}
