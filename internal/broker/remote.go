package broker

import (
	"context"
	"encoding/json"
	"slices"
)

// Live updates of the other replicas' records (several replicas;
// docs/architecture.md, section 5.12.5): the pending approvals, notices
// and review items each replica holds are in the shared store, and every
// replica follows the others'. When they change, this replica publishes
// the events its own would (a new or changed approval, one decided; a
// notice posted, dismissed or gone; a review item, new or judged, or
// gone), so that the approval page, the console and GET /v1/events show
// them as they happen, not only when a page loads. The events name the
// replica that holds the record (Event.Replica): mail and webhooks
// announce an approval or a notice where it is held, once.

// remoteState is what this replica last saw of the others' records: their
// data by id.
type remoteState struct {
	pending, notices, reviews map[string]remoteRecord
}

type remoteRecord struct {
	replica string
	data    string
}

func (b *Broker) remoteRecords(p stateKept) map[string]remoteRecord {
	out := map[string]remoteRecord{}
	if p.table == nil {
		return out
	}
	recs, _ := p.table.Others()
	for id, o := range recs {
		out[id] = remoteRecord{replica: o.Replica, data: string(o.Data)}
	}
	return out
}

func (b *Broker) remoteState() remoteState {
	return remoteState{pending: b.remoteRecords(b.pendingStore), notices: b.remoteRecords(b.noticesStore),
		reviews: b.remoteRecords(b.reviewsStore)}
}

// followRemote publishes the events of the other replicas' records as
// they change, until ctx ends. What there is at the start is not
// announced: a subscriber lists it.
func (b *Broker) followRemote(ctx context.Context) {
	seen := b.remoteState()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.remoteKick:
		}
		now := b.remoteState()
		b.publishRemote(seen, now)
		seen = now
	}
}

// publishRemote publishes the events between two states of the others'
// records.
func (b *Broker) publishRemote(old, now remoteState) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, r := range now.pending {
		was, ok := old.pending[id]
		if (ok && was.data == r.data) || b.pending[id] != nil {
			continue
		}
		var p Pending
		if json.Unmarshal([]byte(r.data), &p) != nil || !p.Expires.After(b.now()) {
			continue
		}
		b.publish(Event{Type: "pending", ID: id, New: !ok, Pending: &p, Replica: r.replica})
	}
	for id, r := range old.pending {
		// Gone there: decided, expired, or adopted here (then it is
		// this replica's, announced as such).
		if _, ok := now.pending[id]; !ok && b.pending[id] == nil {
			b.publish(Event{Type: "resolved", ID: id, Replica: r.replica})
		}
	}
	for id, r := range now.notices {
		was, ok := old.notices[id]
		if (ok && was.data == r.data) || b.notices[id] != nil {
			continue
		}
		var n storedNotice
		if json.Unmarshal([]byte(r.data), &n) != nil || !n.Expires.After(b.now()) {
			continue
		}
		if !ok {
			c := n.Notice
			b.publish(Event{Type: "notice", ID: id, New: true, Notice: &c, Replica: r.replica})
			continue
		}
		// Dismissed by more readers: closed for them.
		var before storedNotice
		_ = json.Unmarshal([]byte(was.data), &before)
		for _, reader := range n.Dismissed {
			if !slices.Contains(before.Dismissed, reader) {
				b.publish(Event{Type: "notice-closed", ID: id, Reader: reader, Replica: r.replica})
			}
		}
	}
	for id, r := range old.notices {
		if _, ok := now.notices[id]; !ok && b.notices[id] == nil {
			b.publish(Event{Type: "notice-closed", ID: id, Replica: r.replica})
		}
	}
	for id, r := range now.reviews {
		was, ok := old.reviews[id]
		if (ok && was.data == r.data) || b.reviews[id] != nil {
			continue
		}
		var rv Review
		if json.Unmarshal([]byte(r.data), &rv) != nil || !rv.Expires.After(b.now()) {
			continue
		}
		c := copyReview(&rv)
		b.publish(Event{Type: "review", ID: id, Review: &c, Replica: r.replica})
	}
	for id, r := range old.reviews {
		if _, ok := now.reviews[id]; !ok && b.reviews[id] == nil {
			b.publish(Event{Type: "review-closed", ID: id, Replica: r.replica})
		}
	}
}
