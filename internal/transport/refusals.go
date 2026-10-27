package transport

import (
	"net/http"
	"sync"
	"time"
)

// Refusals are logged so that an administrator can tell why a client
// gets a 4xx (an agent often says no more than "4xx"), but a client that
// signs in with OAuth starts with a 401, and scanners try any path: per
// reason, the first refusalBurst in each refusalWindow are logged, and
// the next one logged after that says how many were left out.
const (
	refusalBurst  = 5
	refusalWindow = time.Minute
)

type refusalLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	reasons map[string]*refusalCount
}

type refusalCount struct {
	start      time.Time
	logged     int
	suppressed int
}

// allow reports whether a refusal for reason is logged now and how many
// of its refusals were not since the last one that was.
func (l *refusalLimiter) allow(reason string) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	c := l.reasons[reason]
	if c == nil {
		if l.reasons == nil {
			l.reasons = map[string]*refusalCount{}
		}
		c = &refusalCount{start: now}
		l.reasons[reason] = c
	}
	if now.Sub(c.start) >= refusalWindow {
		c.start, c.logged = now, 0
	}
	if c.logged >= refusalBurst {
		c.suppressed++
		return false, 0
	}
	c.logged++
	n := c.suppressed
	c.suppressed = 0
	return true, n
}

// logRefusal logs a refused request: its status, why (reason, which also
// keys the rate limit, and attrs), and from where.
func (h *HTTPHandler) logRefusal(r *http.Request, status int, reason string, attrs ...any) {
	ok, suppressed := h.refusals.allow(reason)
	if !ok {
		return
	}
	args := append([]any{"status", status, "reason", reason, "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr}, attrs...)
	if suppressed > 0 {
		args = append(args, "suppressed", suppressed)
	}
	h.log.Info("HTTP request refused", args...)
}

// refuse answers with status and msg as text (http.Error) and logs it.
func (h *HTTPHandler) refuse(w http.ResponseWriter, r *http.Request, status int, msg, reason string, attrs ...any) {
	h.logRefusal(r, status, reason, attrs...)
	http.Error(w, msg, status)
}
