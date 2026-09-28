package audit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
)

// Record is one enforcement decision.
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
	// DecisionID correlates this record with OPA's decision log (it is
	// passed to OPA as input.context.decision_id).
	DecisionID string
	// Args are logged as a keyed digest, or verbatim with FullArgs (the
	// policy's audit: full obligation).
	Args     map[string]any
	FullArgs bool
	// Reidentified counts the pseudonyms replaced by original values in
	// the arguments (Args are then the arguments as forwarded).
	Reidentified int
}

// KernelSender delivers messages to the kernel audit subsystem.
type KernelSender interface {
	Send(msg string) error
}

// Options configure a Logger.
type Options struct {
	// Key keys the argument digests (HMAC-SHA256), so logged digests
	// cannot be matched against guessed argument values without it.
	// Without a key, digests are plain SHA-256.
	Key []byte
	// Kernel, if set, receives security-relevant events: denials,
	// approval decisions, grant revocations, policy changes.
	Kernel KernelSender
}

// Logger writes audit records as JSON lines to w (journald picks them up
// from stderr) and security-relevant ones to the kernel audit subsystem,
// where they can be correlated with SELinux AVC records.
type Logger struct {
	l    *slog.Logger
	opts Options

	warnOnce sync.Once
}

// New returns a logger writing to w.
func New(w io.Writer, opts ...Options) *Logger {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	return &Logger{l: slog.New(slog.NewJSONHandler(w, nil)).With("audit", true), opts: o}
}

// Log writes r; denials also go to the kernel audit subsystem.
func (a *Logger) Log(r Record) {
	if a == nil {
		return
	}
	attrs := []any{
		"session", r.Session, "sub", r.Sub, "action", r.Action,
		"server", r.Server, "effect", r.Effect,
	}
	for _, kv := range [][2]string{{"name", r.Name}, {"reason", r.Reason}, {"grant", r.GrantID},
		{"instance", r.Instance}, {"decision_id", r.DecisionID}} {
		if kv[1] != "" {
			attrs = append(attrs, kv[0], kv[1])
		}
	}
	if r.Reidentified > 0 {
		attrs = append(attrs, "reidentified", r.Reidentified)
	}
	if r.Args != nil {
		if r.FullArgs {
			attrs = append(attrs, "args", r.Args)
		} else {
			attrs = append(attrs, "args_hmac", a.digest(r.Args))
		}
	}
	a.l.Info("mcp", attrs...)
	if r.Effect == "deny" {
		a.kernel("mcp-decision", false, map[string]string{
			"session": r.Session, "principal": r.Sub, "action": r.Action, "server": r.Server,
			"target": r.Name, "reason": r.Reason, "decision_id": r.DecisionID,
		})
	}
}

// Event records a security-relevant event that is not a decision: an
// approval decided, a grant revoked, the policy changed. ok maps to the
// audit record's res=success/failed.
func (a *Logger) Event(op string, ok bool, fields map[string]string) {
	if a == nil {
		return
	}
	attrs := []any{"event", op, "ok", ok}
	keys := sortedKeys(fields)
	for _, k := range keys {
		attrs = append(attrs, k, fields[k])
	}
	a.l.Info("mcp", attrs...)
	a.kernel(op, ok, fields)
}

// Note records an audit event in the journal only: routine events that
// matter for review but not for the kernel audit trail (for example what
// was pseudonymized in a result).
func (a *Logger) Note(op string, fields map[string]string) {
	if a == nil {
		return
	}
	attrs := []any{"event", op}
	for _, k := range sortedKeys(fields) {
		attrs = append(attrs, k, fields[k])
	}
	a.l.Info("mcp", attrs...)
}

func (a *Logger) kernel(op string, ok bool, fields map[string]string) {
	if a.opts.Kernel == nil {
		return
	}
	if err := a.opts.Kernel.Send(FormatKernel(op, ok, fields)); err != nil {
		a.warnOnce.Do(func() {
			a.l.Warn("sending to the kernel audit subsystem failed", "err", err)
		})
	}
}

func (a *Logger) digest(v any) string {
	b, _ := json.Marshal(v)
	if len(a.opts.Key) == 0 {
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:])
	}
	m := hmac.New(sha256.New, a.opts.Key)
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil))
}

// Digest returns the SHA-256 of the canonical JSON encoding of v (object
// keys sorted).
func Digest(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// FormatKernel formats an audit message the way the audit tools expect:
// "op=<op> key=value ... res=success|failed". Values that are not plain
// tokens are hex-encoded (as auditd does for untrusted strings); empty
// values are left out.
func FormatKernel(op string, ok bool, fields map[string]string) string {
	var b strings.Builder
	b.WriteString("op=")
	b.WriteString(op)
	for _, k := range sortedKeys(fields) {
		v := fields[k]
		if v == "" {
			continue
		}
		b.WriteString(" ")
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(auditValue(v))
	}
	if ok {
		b.WriteString(" res=success")
	} else {
		b.WriteString(" res=failed")
	}
	return b.String()
}

func auditValue(v string) string {
	for _, c := range v {
		plain := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.:/@+-", c)
		if !plain {
			return strings.ToUpper(hex.EncodeToString([]byte(v)))
		}
	}
	return v
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// LoadKey reads the digest key at path, creating a random one (mode
// 0600) if the file does not exist.
func LoadKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) < 32 {
			return nil, fmt.Errorf("audit key %s is too short", path)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(key); err != nil {
		_ = f.Close()
		return nil, err
	}
	return key, f.Close()
}
