package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Reviews: a tool call that policy marked with the obligation "review"
// becomes a review item once it ran. Its reviewers are those who may
// decide on the call as an approval (approver rule allow, with the call
// as input.request); a reviewer gives a verdict, "ok" or "incident" (an
// action that should not have run), which a later verdict replaces.
const (
	// ReviewTTL is how long a review item is kept.
	ReviewTTL = 7 * 24 * time.Hour
	// MaxReviews bounds the review items kept; the oldest go first.
	MaxReviews = 5000
	// MaxReviewReason bounds a verdict's reason (bytes).
	MaxReviewReason = 1000
)

// Verdicts.
const (
	VerdictOK       = "ok"
	VerdictIncident = "incident"
)

// ErrBadVerdict means a verdict is malformed (the error says how).
var ErrBadVerdict = errors.New("broker: invalid verdict")

// Review is a call that ran, to review.
type Review struct {
	ID string `json:"id"`
	// The call: as an approval shows it.
	Principal principal.Principal `json:"principal"`
	Action    string              `json:"action"`
	Server    string              `json:"server"`
	Name      string              `json:"name"`
	// Args are the call's arguments where the policy's audit obligation
	// records them ("full"); absent otherwise.
	Args map[string]any `json:"args,omitempty"`
	// What allowed it: the decision, and the approval and grant if any.
	DecisionID string `json:"decision_id"`
	ApprovalID string `json:"approval_id,omitempty"`
	GrantID    string `json:"grant,omitempty"`
	// Its outcome (as in its mcp-result record) and when it ran.
	Outcome    string    `json:"outcome"`
	Error      string    `json:"error,omitempty"`
	Ran        time.Time `json:"ran"`
	DurationMS int64     `json:"duration_ms"`
	Created    time.Time `json:"created"`
	Expires    time.Time `json:"expires"`
	// Verdict is the latest verdict, if there is one.
	Verdict *Verdict `json:"verdict,omitempty"`
}

// Verdict is a reviewer's judgement of a call.
type Verdict struct {
	Verdict string    `json:"verdict"`
	Reason  string    `json:"reason,omitempty"`
	By      string    `json:"by"`
	At      time.Time `json:"at"`
	Via     string    `json:"via,omitempty"`
}

// ReviewTarget is a review item as approver rules see it (input.review);
// input.request is its call.
type ReviewTarget struct {
	ID         string `json:"id"`
	DecisionID string `json:"decision_id"`
	Outcome    string `json:"outcome"`
}

func (r *Review) input() ApproverInput {
	return ApproverInput{
		Request: &ApprovalTarget{Principal: r.Principal, Server: r.Server, Name: r.Name, Action: r.Action},
		Review:  &ReviewTarget{ID: r.ID, DecisionID: r.DecisionID, Outcome: r.Outcome},
	}
}

// AsPending is the call of r as a pending approval, for what asks the
// user's password for their own decision (OwnPassword).
func (r *Review) AsPending() Pending {
	return Pending{ID: r.ID, Principal: r.Principal, Action: r.Action, Server: r.Server, Name: r.Name}
}

// reviewPrincipal is the part of a principal a review item keeps: what
// approver rules decide on, and the client as it named itself.
func reviewPrincipal(p principal.Principal) principal.Principal {
	return principal.Principal{Sub: p.Sub, Issuer: p.Issuer, UID: p.UID, Transport: p.Transport, Client: p.Client}
}

// AddReview keeps r, a call that ran, for review, and announces it. The
// id and times are set here.
func (b *Broker) AddReview(r Review) Review {
	r.Principal = reviewPrincipal(r.Principal)
	r.ID = "r-" + randomHex(16)
	r.Created = b.now().UTC()
	r.Expires = r.Created.Add(ReviewTTL)
	r.Verdict = nil
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneReviews()
	if b.reviews == nil {
		b.reviews = map[string]*Review{}
	}
	for len(b.reviews) >= MaxReviews {
		b.dropOldestReview()
	}
	c := r
	b.reviews[r.ID] = &c
	b.persistReviews()
	e := r
	b.publish(Event{Type: "review", ID: r.ID, New: true, Review: &e})
	b.log.Info("review item", "id", r.ID, "decision_id", r.DecisionID, "sub", r.Principal.Sub, "server", r.Server, "name", r.Name)
	return r
}

// MayReview reports whether a may review r: as for deciding on its call
// (approver rule allow); without policy, the principal themself.
func (b *Broker) MayReview(ctx context.Context, a Approver, r Review) bool {
	if b.opts.Policy == nil && !a.Root() {
		return a.owns(r.Principal.UID)
	}
	return b.ask(ctx, a, approvePath, r.input())
}

// ListReviews returns the unexpired review items a may review, oldest
// first, with their verdicts.
func (b *Broker) ListReviews(ctx context.Context, a Approver) []Review {
	b.mu.Lock()
	b.pruneReviews()
	all := make([]Review, 0, len(b.reviews))
	for _, r := range b.reviews {
		all = append(all, copyReview(r))
	}
	b.mu.Unlock()
	out := []Review{}
	for _, r := range all {
		if b.MayReview(ctx, a, r) {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(x, y Review) int { return x.Created.Compare(y.Created) })
	return out
}

// GetReview returns review item id if a may review it.
func (b *Broker) GetReview(ctx context.Context, a Approver, id string) (Review, error) {
	b.mu.Lock()
	b.pruneReviews()
	r, ok := b.reviews[id]
	var c Review
	if ok {
		c = copyReview(r)
	}
	b.mu.Unlock()
	if !ok || !b.MayReview(ctx, a, c) {
		return Review{}, ErrNotFound
	}
	return c, nil
}

// ReviewOwnOnly reports whether a may review item id only as its
// principal ("self"), as OwnOnly does for approvals: such a verdict over
// the control socket needs the user's password.
func (b *Broker) ReviewOwnOnly(ctx context.Context, a Approver, id string) (bool, error) {
	if a.Root() || a.Remote {
		return false, nil
	}
	r, err := b.GetReview(ctx, a, id)
	if err != nil {
		return false, err
	}
	if b.opts.Policy == nil {
		return a.owns(r.Principal.UID), nil
	}
	in := r.input()
	in.Approver = a.policyView()
	ok, err := b.opts.Policy.Bool(ctx, approveOthersPath, in)
	if err != nil && !errors.Is(err, pep.ErrUndefined) {
		b.log.Warn("approver policy failed", "path", approveOthersPath, "err", err)
	}
	return !ok, nil
}

// Judge records a's verdict on review item id, replacing an earlier one,
// and audits it (mcp-review). via names the way it came, as for
// approvals ("" leaves it out).
func (b *Broker) Judge(ctx context.Context, a Approver, id, verdict, reason, via string) (Review, error) {
	reason = strings.TrimSpace(reason)
	switch {
	case verdict != VerdictOK && verdict != VerdictIncident:
		return Review{}, fmt.Errorf("%w: verdict must be %q or %q", ErrBadVerdict, VerdictOK, VerdictIncident)
	case verdict == VerdictIncident && reason == "":
		return Review{}, fmt.Errorf("%w: an incident needs a reason", ErrBadVerdict)
	case len(reason) > MaxReviewReason || !plainText(reason, true):
		return Review{}, fmt.Errorf("%w: the reason must be plain text of at most %d bytes", ErrBadVerdict, MaxReviewReason)
	}
	if _, err := b.GetReview(ctx, a, id); err != nil {
		return Review{}, err
	}
	b.mu.Lock()
	r, ok := b.reviews[id]
	if !ok {
		b.mu.Unlock()
		return Review{}, ErrNotFound
	}
	r.Verdict = &Verdict{Verdict: verdict, Reason: reason, By: a.Name, At: b.now().UTC(), Via: via}
	b.persistReviews()
	c := copyReview(r)
	e := c
	b.publish(Event{Type: "review", ID: id, Review: &e})
	b.mu.Unlock()
	if b.opts.Audit != nil {
		fields := map[string]string{"id": id, "decision_id": c.DecisionID, "sub": c.Principal.Sub, "server": c.Server,
			"name": c.Name, "verdict": verdict, "reason": reason, "by": a.Name}
		if a.Remote {
			fields["issuer"] = a.Issuer
		}
		if via != "" {
			fields["via"] = via
		}
		b.opts.Audit.Event("mcp-review", verdict == VerdictOK, fields)
	}
	return c, nil
}

func copyReview(r *Review) Review {
	c := *r
	if r.Verdict != nil {
		v := *r.Verdict
		c.Verdict = &v
	}
	return c
}

// pruneReviews drops expired review items. Caller holds b.mu.
func (b *Broker) pruneReviews() {
	changed := false
	for id, r := range b.reviews {
		if !r.Expires.After(b.now()) {
			delete(b.reviews, id)
			b.publish(Event{Type: "review-closed", ID: id})
			changed = true
		}
	}
	if changed {
		b.persistReviews()
	}
}

// dropOldestReview makes room for a new item. Caller holds b.mu.
func (b *Broker) dropOldestReview() {
	var oldest *Review
	for _, r := range b.reviews {
		if oldest == nil || r.Created.Before(oldest.Created) {
			oldest = r
		}
	}
	if oldest != nil {
		delete(b.reviews, oldest.ID)
		b.publish(Event{Type: "review-closed", ID: oldest.ID})
	}
}

// loadReviews restores the review items of a previous run.
func (b *Broker) loadReviews() error {
	if b.opts.ReviewsFile == "" {
		return nil
	}
	data, err := os.ReadFile(b.opts.ReviewsFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var list []*Review
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("broker: reading %s: %w", b.opts.ReviewsFile, err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reviews = map[string]*Review{}
	for _, r := range list {
		if r.ID != "" && r.Expires.After(b.now()) {
			b.reviews[r.ID] = r
		}
	}
	return nil
}

// persistReviews writes the review items. Caller holds b.mu.
func (b *Broker) persistReviews() {
	if b.opts.ReviewsFile == "" {
		return
	}
	list := make([]*Review, 0, len(b.reviews))
	for _, r := range b.reviews {
		list = append(list, r)
	}
	slices.SortFunc(list, func(x, y *Review) int { return x.Created.Compare(y.Created) })
	data, err := json.MarshalIndent(list, "", "  ")
	if err == nil {
		err = writeFileAtomic(b.opts.ReviewsFile, append(data, '\n'))
	}
	if err != nil {
		b.log.Warn("persisting review items failed", "err", err)
	}
}

// ReviewURL is the page of review item id on an approval page of the
// gateway's kind (a url_template ending in "/{id}" without a fragment,
// which Cockpit's has); else "".
func (b *Broker) ReviewURL(id string) string {
	if base := b.NoticesURL(); base != "" && !strings.Contains(base, "#") {
		return base + "reviews/" + id
	}
	return ""
}
