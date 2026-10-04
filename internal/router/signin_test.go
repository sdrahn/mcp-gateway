package router

import (
	"context"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/signin"
)

// fakeSignIns signs in at once (Run) and records starts (Prepare).
type fakeSignIns struct {
	mu       sync.Mutex
	signed   map[string]bool
	runs     int
	prepared int
	// refuse makes the next Prepare report that the tokens were refused.
	refuse   bool
	rejected int
	// changed records DefinitionChanged: "old->next" by url, "-" for nil.
	changed []string
}

func (f *fakeSignIns) DefinitionChanged(old, next *config.Backend) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := "-"
	if next != nil {
		n = next.URL
	}
	f.changed = append(f.changed, old.Name+":"+old.URL+"->"+n)
}

func (f *fakeSignIns) Rejected(string, principal.Principal) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejected++
}

func (f *fakeSignIns) Signed(p principal.Principal, server string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.signed[p.Sub+"/"+server]
}

func (f *fakeSignIns) Run(_ context.Context, _ broker.Elicitor, b *config.Backend, p principal.Principal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs++
	f.signed[p.Sub+"/"+b.Name] = true
	return nil
}

func (f *fakeSignIns) Prepare(_ context.Context, b *config.Backend, p principal.Principal) (*config.Backend, func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse {
		f.refuse = false
		delete(f.signed, p.Sub+"/"+b.Name)
		return nil, nil, signin.ErrNotSignedIn
	}
	f.prepared++
	nb := *b
	nb.Credentials = append(nb.Credentials, "sign-in:/run/x")
	return &nb, func() {}, nil
}

func TestSignIn(t *testing.T) {
	r, l := testRouter(t, time.Minute)
	si := &fakeSignIns{signed: map[string]bool{}}
	r.SignIns = si
	r.Backends["tickets"] = &config.Backend{Name: "tickets", Isolation: config.IsolationPrincipal,
		Discovery: config.DiscoveryInstance, SignIn: &config.SignIn{}}
	c := connect(t, r, alice(), "", nil)

	// Before signing in: only the sign-in tool, and no instance.
	got := strings.Join(names(t, c.roundTrip(1, "tools/list", map[string]any{}), "tools", "name"), ",")
	if !strings.Contains(got, "tickets__sign_in") || strings.Contains(got, "tickets__read_file") || len(l.started("tickets")) != 0 {
		t.Fatalf("tools before sign-in: %s", got)
	}
	text, isErr := toolText(t, c.roundTrip(2, "tools/call", map[string]any{"name": "tickets__sign_in"}))
	if isErr || !strings.Contains(text, "Signed in to tickets") || si.runs != 1 {
		t.Fatalf("sign_in: %q %v", text, isErr)
	}
	got = strings.Join(names(t, c.roundTrip(3, "tools/list", map[string]any{}), "tools", "name"), ",")
	if strings.Contains(got, "tickets__sign_in") || !strings.Contains(got, "tickets__read_file") || si.prepared != 1 {
		t.Fatalf("tools after sign-in: %s (prepared %d)", got, si.prepared)
	}

	// Signing out stops the principal's instance and tells the session.
	r.SignInChanged(signin.KeyOf(alice()), "tickets", false)
	si.mu.Lock()
	si.signed = map[string]bool{}
	si.mu.Unlock()
	if m := c.read(); m.Method != "notifications/tools/list_changed" {
		t.Fatalf("got %+v", m)
	}
	for range 2 {
		c.read() // prompts, resources
	}
	waitFor(t, func() bool {
		select {
		case <-l.started("tickets")[0].closed:
			return true
		default:
			return false
		}
	})

	// A tool call without a token signs in first, then goes on.
	if text, _ := toolText(t, c.roundTrip(4, "tools/call", map[string]any{"name": "tickets__read_file"})); text != "tickets did read_file" || si.runs != 2 {
		t.Fatalf("call: %q, runs %d", text, si.runs)
	}

	// Tokens refused at refresh (the instance gone): sign in again.
	r.StopInstance(l.started("tickets")[1].id)
	si.mu.Lock()
	si.refuse = true
	si.mu.Unlock()
	if text, _ := toolText(t, c.roundTrip(5, "tools/call", map[string]any{"name": "tickets__read_file"})); text != "tickets did read_file" || si.runs != 3 {
		t.Fatalf("after refusal: %q, runs %d", text, si.runs)
	}
}

// A definition changed or removed is passed to the sign-ins with the
// previous one, so that tokens that no longer fit go.
func TestSignInDefinitionChanged(t *testing.T) {
	r, _ := testRouter(t, time.Minute)
	si := &fakeSignIns{signed: map[string]bool{}}
	r.SignIns = si
	tickets := &config.Backend{Name: "tickets", URL: "https://a/mcp", SignIn: &config.SignIn{}}
	r.Backends["tickets"] = tickets
	next := maps.Clone(r.CurrentBackends())
	next["tickets"] = &config.Backend{Name: "tickets", URL: "https://b/mcp", SignIn: &config.SignIn{}}
	r.SetBackends(next)
	next = maps.Clone(next)
	delete(next, "tickets")
	r.SetBackends(next)
	if got := strings.Join(si.changed, " "); got != "tickets:https://a/mcp->https://b/mcp tickets:https://b/mcp->-" {
		t.Errorf("changes: %s", got)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
