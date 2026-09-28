package pep

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/pseudo"
)

// StringList unmarshals from a JSON string or a list of strings.
type StringList []string

// UnmarshalJSON implements json.Unmarshaler.
func (l *StringList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*l = StringList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return errors.New("expected a string or a list of strings")
	}
	*l = many
	return nil
}

// Redacted replaces redacted output.
const Redacted = "[redacted]"

// Rate is a compiled rate limit: N events per Per.
type Rate struct {
	N   int
	Per time.Duration
}

// Compiled are obligations ready to be enforced.
type Compiled struct {
	Redact         []*regexp.Regexp
	MaxOutputBytes int64
	Rates          []Rate
	ArgConstraints map[string][]*regexp.Regexp
	FullAudit      bool
	// Pseudo is nil when nothing is to be pseudonymized.
	Pseudo     *pseudo.Compiled
	Reidentify []string
}

// Compile validates o. Any malformed obligation makes the whole decision
// invalid, which fails closed.
func (o *Obligations) Compile() (*Compiled, error) {
	c := &Compiled{ArgConstraints: map[string][]*regexp.Regexp{}}
	if o == nil {
		return c, nil
	}
	for _, p := range o.RedactOutput {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("obligation redact_output %q: %w", p, err)
		}
		c.Redact = append(c.Redact, re)
	}
	if o.MaxOutputBytes < 0 {
		return nil, errors.New("obligation max_output_bytes: must not be negative")
	}
	c.MaxOutputBytes = o.MaxOutputBytes
	for _, r := range o.RateLimit {
		rate, err := ParseRate(r)
		if err != nil {
			return nil, err
		}
		c.Rates = append(c.Rates, rate)
	}
	for name, patterns := range o.ArgConstraints {
		for _, p := range patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("obligation arg_constraints %s: %w", name, err)
			}
			c.ArgConstraints[name] = append(c.ArgConstraints[name], re)
		}
	}
	pc, err := pseudo.Compile(o.Pseudonymize)
	if err != nil {
		return nil, fmt.Errorf("obligation %w", err)
	}
	c.Pseudo = pc
	for _, name := range o.Reidentify {
		if name == "" {
			return nil, errors.New("obligation reidentify: empty argument name")
		}
		c.Reidentify = append(c.Reidentify, name)
	}
	switch o.Audit {
	case "", "digest":
	case "full":
		c.FullAudit = true
	default:
		return nil, fmt.Errorf("obligation audit: unknown value %q", o.Audit)
	}
	return c, nil
}

// ParseRate parses "N/s", "N/m" or "N/h".
func ParseRate(s string) (Rate, error) {
	n, unit, ok := strings.Cut(s, "/")
	count, err := strconv.Atoi(n)
	if !ok || err != nil || count <= 0 {
		return Rate{}, fmt.Errorf("obligation rate_limit %q: want N/s, N/m or N/h", s)
	}
	per := map[string]time.Duration{"s": time.Second, "m": time.Minute, "h": time.Hour}[unit]
	if per == 0 {
		return Rate{}, fmt.Errorf("obligation rate_limit %q: want N/s, N/m or N/h", s)
	}
	return Rate{N: count, Per: per}, nil
}

// CheckArgs reports the first argument violating a constraint.
func (c *Compiled) CheckArgs(args map[string]any) error {
	for name, res := range c.ArgConstraints {
		v, ok := args[name].(string)
		if !ok {
			return fmt.Errorf("argument %q violates a constraint", name)
		}
		for _, re := range res {
			if !re.MatchString(v) {
				return fmt.Errorf("argument %q violates a constraint", name)
			}
		}
	}
	return nil
}

// ApplyOutput redacts result, pseudonymizes it with the session's vault
// and enforces the size limit, in this order. It returns the new result
// and what was pseudonymized, or an error if the result cannot be
// released (too large, or pseudonymization impossible).
func (c *Compiled) ApplyOutput(result json.RawMessage, vault *pseudo.Vault) (json.RawMessage, pseudo.Stats, error) {
	if len(c.Redact) > 0 {
		var v any
		if err := json.Unmarshal(result, &v); err != nil {
			return nil, nil, err
		}
		v = c.redact(v)
		b, err := json.Marshal(v)
		if err != nil {
			return nil, nil, err
		}
		result = b
	}
	var stats pseudo.Stats
	if c.Pseudo != nil {
		if vault == nil {
			return nil, nil, errors.New("pseudonymization required but not available")
		}
		var err error
		if result, stats, err = vault.Apply(c.Pseudo, result); err != nil {
			return nil, nil, err
		}
	}
	if c.MaxOutputBytes > 0 && int64(len(result)) > c.MaxOutputBytes {
		return nil, nil, fmt.Errorf("result of %d bytes exceeds the limit of %d", len(result), c.MaxOutputBytes)
	}
	return result, stats, nil
}

func (c *Compiled) redact(v any) any {
	switch x := v.(type) {
	case string:
		for _, re := range c.Redact {
			x = re.ReplaceAllLiteralString(x, Redacted)
		}
		return x
	case []any:
		for i := range x {
			x[i] = c.redact(x[i])
		}
		return x
	case map[string]any:
		for k := range x {
			x[k] = c.redact(x[k])
		}
		return x
	}
	return v
}

// Limiter enforces rate-limit obligations with sliding windows per key.
type Limiter struct {
	now func() time.Time

	mu     sync.Mutex
	events map[string][]time.Time
}

// NewLimiter returns an empty limiter.
func NewLimiter() *Limiter {
	return &Limiter{now: time.Now, events: map[string][]time.Time{}}
}

// Allow records an event for key if every rate still permits it.
func (l *Limiter) Allow(key string, rates []Rate) bool {
	if len(rates) == 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	var window time.Duration
	for _, r := range rates {
		window = max(window, r.Per)
	}
	kept := l.events[key][:0]
	for _, t := range l.events[key] {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	for _, r := range rates {
		n := 0
		for _, t := range kept {
			if now.Sub(t) < r.Per {
				n++
			}
		}
		if n >= r.N {
			l.events[key] = kept
			return false
		}
	}
	l.events[key] = append(kept, now)
	return true
}
