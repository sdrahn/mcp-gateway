package signin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Agents of MCP 2026-07-28 sign in with a multi round-trip request
// (docs/architecture.md, section 5.11.2): the call that needs the
// sign-in is answered with the link as a URL-mode input request, and the
// agent's retries wait for the callback, each for a bounded time.

// ErrStillWaiting is returned by Await when the sign-in has not completed
// within the wait.
var ErrStillWaiting = errors.New("the sign-in has not completed yet")

// Link starts p's sign-in to b, or returns the one already pending: the
// id of the sign-in (its state) and the URL elicitation that offers the
// link.
func (m *Manager) Link(ctx context.Context, b *config.Backend, p principal.Principal) (string, broker.URLElicitParams, error) {
	pd := m.pendingOf(b.Name, KeyOf(p))
	if pd == nil {
		var err error
		if pd, err = m.Begin(ctx, b, p); err != nil {
			return "", broker.URLElicitParams{}, err
		}
	}
	return pd.State, broker.URLElicitParams{Mode: "url", ElicitationID: pd.State, URL: pd.URL,
		Message: fmt.Sprintf("Sign in to %s with your account there to use its tools. The gateway keeps the token; your agent never sees it.", b.Name)}, nil
}

// LinkError returns the link of p's sign-in to b for a client that
// cannot open links (the agent shows it), starting the sign-in if none
// is pending.
func (m *Manager) LinkError(ctx context.Context, b *config.Backend, p principal.Principal) error {
	pd := m.pendingOf(b.Name, KeyOf(p))
	if pd == nil {
		var err error
		if pd, err = m.Begin(ctx, b, p); err != nil {
			return err
		}
	}
	return &LinkError{Server: b.Name, URL: m.startURL(pd), Expires: pd.Expires}
}

// Await waits up to wait for p's sign-in id to server to complete: nil
// once it did, ErrStillWaiting if it did not yet, ErrTimeout if it is not
// pending (any more) and p is not signed in, or the error it failed with.
func (m *Manager) Await(ctx context.Context, server, id string, p principal.Principal, wait time.Duration) error {
	pd := m.pendingByState(id)
	if pd == nil || pd.Server != server || !pd.Key.Same(KeyOf(p)) {
		if m.Signed(p, server) {
			return nil
		}
		return ErrTimeout
	}
	if left := time.Until(pd.Expires); left < wait {
		wait = left
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case err, ok := <-pd.done:
		if !ok {
			// Another retry took the result.
			if m.Signed(p, pd.Server) {
				return nil
			}
			return ErrTimeout
		}
		return err
	case <-t.C:
		return ErrStillWaiting
	case <-ctx.Done():
		return ErrStillWaiting
	}
}

// Abandon ends the sign-in id of p: the client declined to open the link.
func (m *Manager) Abandon(id string, p principal.Principal) {
	pd := m.pendingByState(id)
	if pd == nil || !pd.Key.Same(KeyOf(p)) {
		return
	}
	if m.take(id) != nil {
		pd.finish(ErrDeclined)
		m.Audit.Event("mcp-sign-in", false, map[string]string{"server": pd.Server, "principal": p.Sub, "step": "failed", "reason": "declined"})
	}
}
