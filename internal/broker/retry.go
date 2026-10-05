package broker

import (
	"context"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Agents of MCP 2026-07-28 have no session for a call to wait in: an
// approval becomes a multi round-trip request (docs/architecture.md,
// section 5.11.2). The first call asks for the approval and is answered
// at once; the agent calls again with the answer to a form, or to wait
// for a decision on the approval page or in the inbox, each retry for a
// bounded time.

// FormParams returns the form that asks the client for an approval.
func FormParams(in pep.Input, ask pep.AskSpec) ElicitParams {
	ask = withScopes(ask)
	return formParams(in, ask.Prompt, ask.Scopes)
}

// FormAnswer records the client's answer to the form of FormParams: the
// grant (a "once" grant is returned, not stored), nil if declined.
func (b *Broker) FormAnswer(in pep.Input, ask pep.AskSpec, res ElicitResult) (*pep.Grant, error) {
	return b.formAnswer(in, withScopes(ask), res)
}

// Park registers a pending approval of in through channel c (url or oob)
// that no call waits for, and returns its id; the approval of the same
// request already pending without a waiting call is taken over.
func (b *Broker) Park(in pep.Input, ask pep.AskSpec, c pep.Channel) string {
	return b.addPending(in, withScopes(ask), c, false).ID
}

// URLParams returns the URL elicitation that offers the client the page
// of approval id.
func (b *Broker) URLParams(in pep.Input, ask pep.AskSpec, id string) URLElicitParams {
	return b.urlParams(in, ask, id)
}

// NotifyOOB tells the client where approval id is decided.
func (b *Broker) NotifyOOB(el Elicitor, in pep.Input, id string) { b.notifyOOB(el, in, id) }

// Outcome is what a retry learned about a parked approval.
type Outcome int

const (
	// Waiting: nobody decided yet; the agent retries again.
	Waiting Outcome = iota
	// Decided: decided while the retry waited (a nil grant: denied).
	Decided
	// Gone: the approval is not pending (any more): decided while no
	// retry waited, so its grant is stored for the call (TakeOnce,
	// Grants), or denied, expired or unknown.
	Gone
)

// Await waits up to wait for the decision on parked approval id of who.
func (b *Broker) Await(ctx context.Context, id string, who principal.Principal, wait time.Duration) (*pep.Grant, Outcome) {
	b.mu.Lock()
	b.pruneExpired()
	p, ok := b.pending[id]
	if !ok || !samePrincipal(p.Principal, who) {
		b.mu.Unlock()
		return nil, Gone
	}
	if p.result != nil {
		// Another call waits for it; this one waits as long, and finds
		// the grant stored or the approval still pending.
		b.mu.Unlock()
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
		}
		return nil, Waiting
	}
	ch := make(chan *pep.Grant, 1)
	p.result, p.Waiting = ch, true
	if left := p.Expires.Sub(b.now()); left < wait {
		wait = left
	}
	b.persistPending()
	b.publishPending(p, false)
	b.mu.Unlock()

	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case g := <-ch:
		return g, Decided
	case <-t.C:
	case <-ctx.Done():
	}
	b.mu.Lock()
	if b.pending[id] != p || p.result != ch {
		// Decided meanwhile: the decision is on its way.
		b.mu.Unlock()
		return <-ch, Decided
	}
	defer b.mu.Unlock()
	if !p.Expires.After(b.now()) {
		delete(b.pending, id)
		b.publish(Event{Type: "resolved", ID: id})
		b.persistPending()
		return nil, Gone
	}
	orphan(p)
	b.publishPending(p, false)
	b.persistPending()
	return nil, Waiting
}

// Withdraw drops parked approval id of who: the client declined to open
// its page.
func (b *Broker) Withdraw(id string, who principal.Principal) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.pending[id]
	if !ok || p.result != nil || !samePrincipal(p.Principal, who) {
		return
	}
	delete(b.pending, id)
	b.publish(Event{Type: "resolved", ID: id})
	b.persistPending()
}

// samePrincipal reports whether a and b are the same principal (not
// session).
func samePrincipal(a, b principal.Principal) bool {
	return a.Transport == b.Transport && a.Issuer == b.Issuer && a.Sub == b.Sub && sameUID(a.UID, b.UID)
}
