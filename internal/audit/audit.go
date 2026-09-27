package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
)

// Record is one audit event.
type Record struct {
	Session  string
	Sub      string
	Action   string
	Server   string
	Name     string
	Effect   string
	Reason   string
	GrantID  string
	Instance string
	// Args are logged as a digest only.
	Args map[string]any
}

// Logger writes audit records as JSON lines (journald picks them up from
// stderr). Forwarding to the kernel audit subsystem follows.
type Logger struct {
	l *slog.Logger
}

// New returns a logger writing to w.
func New(w io.Writer) *Logger {
	return &Logger{l: slog.New(slog.NewJSONHandler(w, nil)).With("audit", true)}
}

// Log writes r.
func (a *Logger) Log(r Record) {
	if a == nil {
		return
	}
	attrs := []any{
		"session", r.Session, "sub", r.Sub, "action", r.Action,
		"server", r.Server, "effect", r.Effect,
	}
	for k, v := range map[string]string{"name": r.Name, "reason": r.Reason, "grant": r.GrantID, "instance": r.Instance} {
		if v != "" {
			attrs = append(attrs, k, v)
		}
	}
	if r.Args != nil {
		attrs = append(attrs, "args_sha256", Digest(r.Args))
	}
	a.l.Info("mcp", attrs...)
}

// Digest returns the SHA-256 of the canonical JSON encoding of v (object
// keys sorted).
func Digest(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
