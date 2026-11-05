package broker

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// reviewPolicy: the ops group approves systemd, olga owns agent-ops;
// "self" is the principal's uid, a rule other than self only for those.
type reviewPolicy struct{}

func (reviewPolicy) Bool(_ context.Context, path string, input any) (bool, error) {
	in := input.(ApproverInput)
	if in.Request == nil || in.Review == nil {
		return false, nil
	}
	other := in.Request.Server == "systemd" && contains(in.Approver.Groups, "ops") ||
		in.Request.Principal.Sub == "agent-ops" && in.Approver.Name == "olga"
	self := in.Request.Principal.UID != nil && in.Approver.UID != nil && *in.Request.Principal.UID == *in.Approver.UID
	switch path {
	case approvePath:
		return other || self, nil
	case approveOthersPath:
		return other, nil
	}
	return false, nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

var (
	opsUser   = Approver{Name: "oscar", UID: 1500, Groups: []string{"ops"}}
	agentUser = Approver{Name: "agent-ops", UID: 1600}
)

func restart() Review {
	uid := uint32(1600)
	return Review{Principal: principal.Principal{Sub: "agent-ops", UID: &uid, SessionID: "s-1", Home: "/home/agent-ops"},
		Action: "tools.call", Server: "systemd", Name: "restart_unit", DecisionID: "d-1", Outcome: "ok",
		Ran: time.Now(), DurationMS: 12}
}

func TestReviews(t *testing.T) {
	k := &kernelLog{}
	b := newBroker(t, func(o *Options) {
		o.Policy = reviewPolicy{}
		o.Audit = audit.New(&strings.Builder{}, audit.Options{Kernel: k})
	})
	events, stop := b.Subscribe()
	defer stop()
	r := b.AddReview(restart())
	if !strings.HasPrefix(r.ID, "r-") || r.Principal.SessionID != "" || r.Principal.Home != "" || !r.Expires.Equal(r.Created.Add(ReviewTTL)) {
		t.Fatalf("item %+v", r)
	}
	if ev := <-events; ev.Type != "review" || !ev.New || ev.Review == nil || ev.Review.ID != r.ID {
		t.Fatalf("event %+v", ev)
	}

	// Who may review: the server's approvers, the owner, the principal
	// (self); not others.
	for _, tc := range []struct {
		a    Approver
		want int
	}{{opsUser, 1}, {olga, 1}, {agentUser, 1}, {rootApprover, 1}, {bobby, 0}} {
		if got := b.ListReviews(t.Context(), tc.a); len(got) != tc.want {
			t.Errorf("%s sees %d items, want %d", tc.a.Name, len(got), tc.want)
		}
	}
	if own, err := b.ReviewOwnOnly(t.Context(), agentUser, r.ID); err != nil || !own {
		t.Fatalf("the principal reviews by self only: %v %v", own, err)
	}
	if own, _ := b.ReviewOwnOnly(t.Context(), opsUser, r.ID); own {
		t.Fatal("an approver counted as self only")
	}

	if _, err := b.Judge(t.Context(), bobby, r.ID, VerdictOK, "", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("judged by one who may not: %v", err)
	}
	for name, v := range map[string][2]string{
		"incident without a reason": {VerdictIncident, "  "},
		"unknown verdict":           {"maybe", "x"},
		"long reason":               {VerdictOK, strings.Repeat("r", MaxReviewReason+1)},
		"control characters":        {VerdictIncident, "a\x1bb"},
	} {
		if _, err := b.Judge(t.Context(), opsUser, r.ID, v[0], v[1], ""); !errors.Is(err, ErrBadVerdict) {
			t.Errorf("%s: %v", name, err)
		}
	}
	got, err := b.Judge(t.Context(), opsUser, r.ID, VerdictIncident, "restarted the wrong unit", "cli")
	if err != nil || got.Verdict == nil || got.Verdict.Verdict != VerdictIncident || got.Verdict.By != "oscar" {
		t.Fatalf("incident: %+v %v", got, err)
	}
	if ev := <-events; ev.Type != "review" || ev.New || ev.Review.Verdict == nil {
		t.Fatalf("verdict event %+v", ev)
	}
	// A later verdict replaces it; both are audited.
	if got, err = b.Judge(t.Context(), olga, r.ID, VerdictOK, "", ""); err != nil || got.Verdict.Verdict != VerdictOK || got.Verdict.By != "olga" {
		t.Fatalf("second verdict: %+v %v", got, err)
	}
	if list := b.ListReviews(t.Context(), opsUser); len(list) != 1 || list[0].Verdict.Verdict != VerdictOK {
		t.Fatalf("after the second verdict: %+v", list)
	}
	if len(k.msgs) != 2 || !strings.Contains(k.msgs[0], "op=mcp-review") || !strings.Contains(k.msgs[0], "verdict=incident") ||
		!strings.Contains(k.msgs[0], "by=oscar") || !strings.Contains(k.msgs[0], "decision_id=d-1") || !strings.Contains(k.msgs[0], "res=failed") ||
		!strings.Contains(k.msgs[0], "via=cli") || !strings.Contains(k.msgs[1], "verdict=ok") || !strings.Contains(k.msgs[1], "res=success") {
		t.Fatalf("audit %v", k.msgs)
	}
}

// Review items survive a restart with their verdicts, and expire.
func TestReviewsKeptAndExpired(t *testing.T) {
	file := filepath.Join(t.TempDir(), "reviews.json")
	now := time.Now()
	mod := func(o *Options) { o.Policy = reviewPolicy{}; o.ReviewsFile = file }
	b := newBroker(t, mod)
	b.now = func() time.Time { return now }
	r := b.AddReview(restart())
	if _, err := b.Judge(t.Context(), opsUser, r.ID, VerdictIncident, "wrong unit", ""); err != nil {
		t.Fatal(err)
	}
	b = newBroker(t, mod)
	b.now = func() time.Time { return now }
	got, err := b.GetReview(t.Context(), opsUser, r.ID)
	if err != nil || got.Verdict == nil || got.Verdict.Reason != "wrong unit" {
		t.Fatalf("restored: %+v %v", got, err)
	}
	events, stop := b.Subscribe()
	defer stop()
	now = now.Add(ReviewTTL)
	if list := b.ListReviews(t.Context(), opsUser); len(list) != 0 {
		t.Fatalf("expired item listed: %+v", list)
	}
	if ev := <-events; ev.Type != "review-closed" || ev.ID != r.ID {
		t.Fatalf("expiry event %+v", ev)
	}
}

// Without approver policy, the principal themself reviews.
func TestReviewsWithoutPolicy(t *testing.T) {
	b := newBroker(t, func(o *Options) { o.Policy = nil })
	r := b.AddReview(restart())
	if got := b.ListReviews(t.Context(), agentUser); len(got) != 1 {
		t.Fatalf("the principal: %+v", got)
	}
	if got := b.ListReviews(t.Context(), opsUser); len(got) != 0 {
		t.Fatalf("another user: %+v", got)
	}
	if own, err := b.ReviewOwnOnly(t.Context(), agentUser, r.ID); err != nil || !own {
		t.Fatalf("own only: %v %v", own, err)
	}
}
