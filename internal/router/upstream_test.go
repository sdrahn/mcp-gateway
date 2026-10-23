package router

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

func TestExcerpt(t *testing.T) {
	if got := excerpt([]byte("usage: suseconnect-mcp [flags]"), 200); got != "usage: suseconnect-mcp [flags]" {
		t.Errorf("short line: %q", got)
	}
	long := strings.Repeat("x", 250)
	if got := excerpt([]byte(long), 200); got != strings.Repeat("x", 200)+"…" {
		t.Errorf("long line: %d bytes", len(got))
	}
	// Cut inside a multi-byte character, and invalid UTF-8 from the backend.
	if got := excerpt([]byte("ab\xc3\xa4"), 3); got != "ab�…" {
		t.Errorf("cut rune: %q", got)
	}
	if got := excerpt([]byte("a\xffb"), 200); got != "a�b" {
		t.Errorf("invalid UTF-8: %q", got)
	}
}

// An instance that does not answer initialize within
// supervisor.start_timeout fails to start, with an error naming the key;
// the setting applies to the next start (a reload).
func TestStartTimeout(t *testing.T) {
	r, _ := testRouter(t, 0)
	r.Backends["mute"] = &config.Backend{Name: "mute", Isolation: config.IsolationPrincipal}
	// A second, as a failed start backs off before the next.
	r.Backends["mute2"] = &config.Backend{Name: "mute2", Isolation: config.IsolationPrincipal}
	r.init()
	r.SetSettings(Settings{StartTimeout: 200 * time.Millisecond})
	start := time.Now()
	_, _, err := r.pool.acquire(context.Background(), r.Backends["mute"], alice())
	took := time.Since(start)
	var st *StartTimeoutError
	if !errors.As(err, &st) || err.Error() != "mute did not answer initialize within 200ms (supervisor.start_timeout)" {
		t.Fatalf("err = %v", err)
	}
	if took < 200*time.Millisecond || took > 5*time.Second {
		t.Errorf("gave up after %v, want 200ms", took)
	}
	r.SetSettings(Settings{StartTimeout: 400 * time.Millisecond})
	_, _, err = r.pool.acquire(context.Background(), r.Backends["mute2"], alice())
	if err == nil || !strings.Contains(err.Error(), "within 400ms") {
		t.Errorf("after the change: %v", err)
	}
	// A server that answers is not affected.
	if _, release, err := r.pool.acquire(context.Background(), r.Backends["fs"], alice()); err != nil {
		t.Errorf("fs: %v", err)
	} else {
		release()
	}
}
