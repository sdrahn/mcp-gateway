package broker

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/store"
)

// Changes to a record another replica holds (several replicas;
// docs/architecture.md, section 5.12.5): a decision on a pending approval,
// a notice's dismissal, a review item's verdict. The replica where an
// approver asks for one checks it as it would its own (the approver
// rules, the scope, the verdict) and writes it as a request record; the
// replica that holds the record follows the requests and carries them
// out as its own: a decision wakes the call waiting there and makes the
// grant there (session grants belong to the call's session). A decision
// is claimed by its name (decision/<id>), by the holder too when it
// decides itself: the first decision wins, wherever it was made.
const (
	requestDecision  = "decision"
	requestDismissal = "dismissal"
	requestVerdict   = "verdict"
	// requestTTL is how long a request no replica carried out is kept:
	// its record went away, or it claimed a decision.
	requestTTL = 10 * time.Minute
)

// request is a change asked of the replica that holds a record.
type request struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	// A decision.
	Approve bool   `json:"approve,omitempty"`
	Scope   string `json:"scope,omitempty"`
	// A dismissal: whose.
	Reader string `json:"reader,omitempty"`
	// A verdict.
	Verdict string `json:"verdict,omitempty"`
	Reason  string `json:"reason,omitempty"`
	// Who asked, how, when.
	By     string    `json:"by"`
	Issuer string    `json:"issuer,omitempty"`
	Remote bool      `json:"remote,omitempty"`
	Via    string    `json:"via,omitempty"`
	At     time.Time `json:"at"`
	// Asked is the replica where it was asked (where it was decided).
	Asked string `json:"asked,omitempty"`
}

// requests are the broker's requests with a shared store.
type requests struct {
	c       store.Collection
	mirror  *store.Mirror[request]
	replica string
	kick    chan struct{}
}

// openRequests follows the requests in c until ctx ends, carrying out
// those for this broker's records.
func (b *Broker) openRequests(ctx context.Context, c store.Collection, replica string) error {
	rq := &requests{c: c, replica: replica, kick: make(chan struct{}, 1)}
	rq.mirror = &store.Mirror[request]{C: c, Log: b.log, MinBackoff: sharedBackoff, MaxBackoff: 30 * sharedBackoff,
		Decode: func(data []byte) (request, error) {
			var r request
			err := json.Unmarshal(data, &r)
			return r, err
		},
		OnChange: func() {
			select {
			case rq.kick <- struct{}{}:
			default:
			}
		}}
	if err := rq.mirror.Load(ctx); err != nil {
		return err
	}
	b.requests = rq
	go rq.mirror.Run(ctx)
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			b.applyRequests(ctx)
			select {
			case <-ctx.Done():
				return
			case <-rq.kick:
			case <-tick.C:
			}
		}
	}()
	return nil
}

// askReplica writes r under name: ErrExists if a request of that name is there
// already (a decision someone made first).
func (b *Broker) askReplica(ctx context.Context, name string, r request) error {
	r.At = b.now().UTC()
	r.Asked = b.requests.replica
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = b.requests.c.Create(ctx, name, data)
	return err
}

func decisionName(id string) string { return requestDecision + "/" + id }

// claimDecision claims the decision on approval id for this replica's
// approver a: false if another decision was made first. Without a shared
// store there is nothing to claim.
func (b *Broker) claimDecision(ctx context.Context, a Approver, id string, approve bool, scope, via string) (bool, error) {
	if b.requests == nil {
		return true, nil
	}
	err := b.askReplica(ctx, decisionName(id), request{Kind: requestDecision, ID: id, Approve: approve, Scope: scope,
		By: a.Name, Issuer: a.Issuer, Remote: a.Remote, Via: via})
	if errors.Is(err, store.ErrExists) {
		return false, nil
	}
	return err == nil, err
}

// applyRequests carries out the requests for this replica's records. A
// decision's record stays as its claim until requestTTL (applying it
// again finds the approval decided); a dismissal's or a verdict's goes
// once it is carried out; any request goes after requestTTL.
func (b *Broker) applyRequests(ctx context.Context) {
	items, _ := b.requests.mirror.Items()
	for name, it := range items {
		r := it.Value
		drop := b.now().Sub(r.At) >= requestTTL
		switch r.Kind {
		case requestDecision:
			if r.Asked != b.requests.replica {
				b.applyDecision(r)
			}
		case requestDismissal:
			drop = b.applyDismissal(r) || drop
		case requestVerdict:
			drop = b.applyVerdict(r) || drop
		default:
			drop = true
		}
		if !drop {
			continue
		}
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := b.requests.c.Delete(dctx, name, it.Version)
		cancel()
		if err == nil || errors.Is(err, store.ErrNotFound) {
			b.requests.mirror.Deleted(name)
		}
	}
}

// applyDecision decides this replica's approval as another replica's
// approver did; true if it was this replica's.
func (b *Broker) applyDecision(r request) bool {
	b.mu.Lock()
	p, ok := b.pending[r.ID]
	b.mu.Unlock()
	if !ok {
		return false
	}
	if _, err := b.decide(r.ID, p, r.Approve, r.Scope, r.By, r.Via); err != nil && !errors.Is(err, ErrNotFound) {
		b.log.Warn("approval decided on another replica not carried out", "id", r.ID, "by", r.By, "replica", r.Asked, "err", err)
	} else {
		b.log.Info("approval decided on another replica", "id", r.ID, "by", r.By, "replica", r.Asked)
	}
	return true
}

// applyDismissal dismisses this replica's notice for another replica's
// reader; true if it was this replica's.
func (b *Broker) applyDismissal(r request) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, ok := b.notices[r.ID]
	if !ok {
		return false
	}
	if !containsString(n.Dismissed, r.Reader) {
		n.Dismissed = append(n.Dismissed, r.Reader)
		b.persistNotices()
	}
	b.publish(Event{Type: "notice-closed", ID: r.ID, Reader: r.Reader})
	return true
}

// applyVerdict records another replica's reviewer's verdict on this
// replica's review item; true if it was this replica's.
func (b *Broker) applyVerdict(r request) bool {
	b.mu.Lock()
	rv, ok := b.reviews[r.ID]
	if !ok {
		b.mu.Unlock()
		return false
	}
	if rv.Verdict != nil && rv.Verdict.At.After(r.At) {
		b.mu.Unlock()
		return true // a later verdict is in force
	}
	rv.Verdict = &Verdict{Verdict: r.Verdict, Reason: r.Reason, By: r.By, At: r.At, Via: r.Via}
	b.persistReviews()
	c := copyReview(rv)
	e := c
	b.publish(Event{Type: "review", ID: r.ID, Review: &e})
	b.mu.Unlock()
	b.auditVerdict(c, r.Verdict, r.Reason, r.By, r.Remote, r.Issuer, r.Via)
	return true
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// remoteName is the name of a request that has no claim to make: unique.
func remoteName(kind, id string, parts ...string) string {
	return kind + "/" + id + "/" + strings.Join(append(parts, randomHex(8)), "/")
}
