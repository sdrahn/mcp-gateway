// Package proposal is a client's account of a tools/call: what it means
// to do and why, sent in the call's _meta under Key. The gateway shows it
// with the approval the call raises and with its review item, marked as
// the client's claim. It never forwards it to the server, and policy never
// sees it: a client can write anything in it.
package proposal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Key is the _meta key of a call's proposal.
const Key = "io.github.sdrahn.mcp-gateway/proposal"

// Limits, in bytes or entries.
const (
	MaxSummary      = 300
	MaxImpact       = 1000
	MaxLine         = 300 // each step, warning, context key and value
	MaxSteps        = 10
	MaxWarnings     = 10
	MaxContext      = 10
	MaxTotal        = 4096 // the proposal as the client sent it
	maxContextKey   = 64
	maxContextValue = MaxLine
)

// Proposal is a client's account of a call.
type Proposal struct {
	// Summary is the client's reason for the call, one line.
	Summary string `json:"summary"`
	// Impact is what the client expects the call to change.
	Impact   string            `json:"impact,omitempty"`
	Steps    []string          `json:"steps,omitempty"`
	Context  map[string]string `json:"context,omitempty"`
	Warnings []string          `json:"warnings,omitempty"`
	// ClientSupplied is always true: what the client said, not a fact the
	// gateway checked. It is set by Parse, not taken from the client.
	ClientSupplied bool `json:"client_supplied"`
}

// ErrInvalid means a proposal was malformed or too large: it is dropped,
// the call goes on without it.
var ErrInvalid = errors.New("proposal: invalid")

// Parse reads a proposal as a client sent it. A malformed or oversized
// one is an error wrapping ErrInvalid, saying what is wrong.
func Parse(raw json.RawMessage) (*Proposal, error) {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
	}
	if len(raw) > MaxTotal {
		return nil, bad("%d bytes, more than %d", len(raw), MaxTotal)
	}
	var p Proposal
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, bad("%v", err)
	}
	if dec.More() {
		return nil, bad("trailing data")
	}
	p.ClientSupplied = true
	p.Summary = strings.TrimSpace(p.Summary)
	p.Impact = strings.TrimSpace(p.Impact)
	switch {
	case p.Summary == "":
		return nil, bad("no summary")
	case !line(p.Summary, MaxSummary):
		return nil, bad("summary: one line of plain text, at most %d bytes", MaxSummary)
	case !text(p.Impact, MaxImpact):
		return nil, bad("impact: plain text, at most %d bytes", MaxImpact)
	case len(p.Steps) > MaxSteps:
		return nil, bad("more than %d steps", MaxSteps)
	case len(p.Warnings) > MaxWarnings:
		return nil, bad("more than %d warnings", MaxWarnings)
	case len(p.Context) > MaxContext:
		return nil, bad("more than %d context entries", MaxContext)
	}
	for _, l := range append(slices.Clone(p.Steps), p.Warnings...) {
		if strings.TrimSpace(l) == "" || !line(l, MaxLine) {
			return nil, bad("steps and warnings: non-empty lines of plain text, at most %d bytes each", MaxLine)
		}
	}
	for k, v := range p.Context {
		if k == "" || !line(k, maxContextKey) || !line(v, maxContextValue) {
			return nil, bad("context: keys of at most %d and values of at most %d bytes, one line each", maxContextKey, maxContextValue)
		}
	}
	return &p, nil
}

// line: one line of plain text of at most max bytes.
func line(s string, max int) bool {
	return len(s) <= max && plain(s, false)
}

// text: plain text of at most max bytes, line breaks allowed.
func text(s string, max int) bool {
	return len(s) <= max && plain(s, true)
}

// plain: valid UTF-8 without control characters (but line breaks and
// tabs where lines are allowed) or bidirectional overrides, which could
// make a text read otherwise than it is.
func plain(s string, lines bool) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		switch {
		case lines && (r == '\n' || r == '\t'):
		case unicode.IsControl(r), r == ' ', r == ' ',
			r >= '‪' && r <= '‮', r >= '⁦' && r <= '⁩':
			return false
		}
	}
	return true
}

// Digest is a SHA-256 of the proposal as the gateway keeps and shows it
// (its JSON with sorted context keys), "sha256:<hex>"; "" for nil. It ties
// an approval's audit record to what the approver was shown.
func (p *Proposal) Digest() string {
	if p == nil {
		return ""
	}
	b, err := json.Marshal(p) // map keys are sorted
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Take removes the proposal from a call's _meta (raw, the JSON object),
// so that it is never forwarded, and returns the _meta without it. With
// no proposal, meta comes back unchanged and p and err are nil; with an
// invalid one, the key is removed all the same and err says why.
func Take(meta json.RawMessage) (rest json.RawMessage, p *Proposal, err error) {
	var m map[string]json.RawMessage
	if len(meta) == 0 || json.Unmarshal(meta, &m) != nil {
		return meta, nil, nil
	}
	raw, ok := m[Key]
	if !ok {
		return meta, nil, nil
	}
	delete(m, Key)
	rest, _ = json.Marshal(m)
	p, err = Parse(raw)
	return rest, p, err
}
