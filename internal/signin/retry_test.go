package signin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A modern agent signs in with retries: the link once (the same while
// pending), retries that wait a bounded time, the callback ending the
// wait.
func TestSignInRetries(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	id, link, err := f.m.Link(ctx, f.b, alice)
	if err != nil {
		t.Fatal(err)
	}
	if link.Mode != "url" || link.ElicitationID != id || !strings.Contains(link.URL, "state="+id) {
		t.Fatalf("link %+v", link)
	}
	if again, _, _ := f.m.Link(ctx, f.b, alice); again != id {
		t.Errorf("a second link while pending: %s", again)
	}
	if err := f.m.Await(ctx, "tickets", id, alice, 10*time.Millisecond); !errors.Is(err, ErrStillWaiting) {
		t.Fatalf("before the callback: %v", err)
	}
	bob := alice
	bob.Sub = "bob"
	if err := f.m.Await(ctx, "tickets", id, bob, time.Second); !errors.Is(err, ErrTimeout) {
		t.Errorf("someone else's sign-in: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- f.m.Await(ctx, "tickets", id, alice, 5*time.Second) }()
	if status, _ := browse(t, link.URL); status != 200 {
		t.Fatalf("callback: %d", status)
	}
	if err := <-done; err != nil {
		t.Fatalf("waiting retry: %v", err)
	}
	// Signed in: a retry after the sign-in ended finds the token.
	if err := f.m.Await(ctx, "tickets", id, alice, time.Second); err != nil {
		t.Errorf("later retry: %v", err)
	}

	// Declined.
	if _, _, err := f.m.SignOut(ctx, f.b, KeyOf(alice), "alice"); err != nil {
		t.Fatal(err)
	}
	id, _, _ = f.m.Link(ctx, f.b, alice)
	f.m.Abandon(id, alice)
	if err := f.m.Await(ctx, "tickets", id, alice, time.Second); !errors.Is(err, ErrTimeout) {
		t.Errorf("abandoned: %v", err)
	}

	// Without URL elicitation: the link to show.
	var le *LinkError
	if err := f.m.LinkError(ctx, f.b, alice); !errors.As(err, &le) || !strings.HasPrefix(le.URL, f.gw.URL+"/oauth/start/") {
		t.Errorf("link error: %v", err)
	}
}
