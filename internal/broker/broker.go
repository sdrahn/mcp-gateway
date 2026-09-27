package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Grant lifetimes.
const (
	OnceTTL    = time.Minute
	SessionTTL = 8 * time.Hour
)

// ErrNoChannel means no approval channel usable for this request is
// available; the request must be denied.
var ErrNoChannel = errors.New("broker: no usable approval channel")

// ElicitParams are the params of an MCP elicitation/create request (form
// mode).
type ElicitParams struct {
	Message         string         `json:"message"`
	RequestedSchema map[string]any `json:"requestedSchema"`
}

// ElicitResult is the result of an elicitation/create request.
type ElicitResult struct {
	// Action is "accept", "decline" or "cancel".
	Action  string         `json:"action"`
	Content map[string]any `json:"content,omitempty"`
}

// Elicitor sends a form-mode elicitation to the client of a session.
type Elicitor interface {
	// SupportsForm reports whether the client advertised form elicitation.
	SupportsForm() bool
	Elicit(ctx context.Context, p ElicitParams) (ElicitResult, error)
}

// Broker obtains approvals and keeps grants. The PoC keeps grants in
// memory; a persistent store follows with URL/OOB approvals.
type Broker struct {
	timeout time.Duration
	now     func() time.Time

	mu     sync.Mutex
	grants map[string][]pep.Grant // by session id
}

// New returns a broker whose approvals time out after timeout.
func New(timeout time.Duration) *Broker {
	return &Broker{timeout: timeout, now: time.Now, grants: map[string][]pep.Grant{}}
}

// Grants returns the unexpired grants of a session for server/tool.
func (b *Broker) Grants(p principal.Principal, server, tool string) []pep.Grant {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	var out []pep.Grant
	for _, g := range b.grants[p.SessionID] {
		exp, err := time.Parse(time.RFC3339, g.Expires)
		if err != nil || !exp.After(now) {
			continue
		}
		if g.Sub == p.Sub && g.Server == server && g.Tool == tool {
			out = append(out, g)
		}
	}
	return out
}

// EndSession drops the grants of a session.
func (b *Broker) EndSession(sessionID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.grants, sessionID)
}

// Approve asks a human to approve the request described by in, as the
// policy's ask spec prescribes. It returns the resulting grant, or nil if
// the human declined. A "once" grant is returned but not stored, so it is
// consumed by the single re-evaluation that uses it.
func (b *Broker) Approve(ctx context.Context, el Elicitor, in pep.Input, ask pep.AskSpec) (*pep.Grant, error) {
	channel, err := b.channel(el, ask)
	if err != nil {
		return nil, err
	}
	scopes := ask.Scopes
	if len(scopes) == 0 {
		scopes = []string{"once"}
	}
	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	res, err := el.Elicit(ctx, formParams(in, ask.Prompt, scopes))
	if err != nil {
		return nil, fmt.Errorf("broker: elicitation failed: %w", err)
	}
	if res.Action != "accept" {
		return nil, nil
	}
	scope, _ := res.Content["scope"].(string)
	if !slices.Contains(scopes, scope) {
		return nil, fmt.Errorf("broker: client answered with scope %q not offered", scope)
	}

	ttl := OnceTTL
	storedScope := scope
	switch scope {
	case "once":
	case "session":
		ttl = SessionTTL
	default:
		d, err := time.ParseDuration(scope)
		if err != nil || d <= 0 || d > SessionTTL {
			return nil, fmt.Errorf("broker: invalid scope %q", scope)
		}
		ttl, storedScope = d, "duration"
	}
	g := &pep.Grant{
		ID:         "g-" + randomHex(8),
		Sub:        in.Principal.Sub,
		Server:     in.Resource.Server,
		Tool:       in.Resource.Name,
		Scope:      storedScope,
		SessionID:  in.Principal.SessionID,
		Expires:    b.now().Add(ttl).UTC().Format(time.RFC3339),
		ApprovedBy: in.Principal.Sub,
		Channel:    channel,
	}
	if scope != "once" {
		b.mu.Lock()
		b.grants[g.SessionID] = append(b.grants[g.SessionID], *g)
		b.mu.Unlock()
	}
	return g, nil
}

// channel picks the approval channel. Only form mode exists in the PoC;
// URL and out-of-band approvals follow (docs/architecture.md, section 11).
func (b *Broker) channel(el Elicitor, ask pep.AskSpec) (pep.Channel, error) {
	for _, c := range []string{string(ask.Channel), ask.Fallback} {
		if pep.Channel(c) == pep.ChannelForm && el.SupportsForm() {
			return pep.ChannelForm, nil
		}
	}
	return "", ErrNoChannel
}

var scopeTitles = map[string]string{
	"once":    "Only this call",
	"session": "For this session",
}

func formParams(in pep.Input, prompt string, scopes []string) ElicitParams {
	titles := make([]string, len(scopes))
	for i, s := range scopes {
		if t, ok := scopeTitles[s]; ok {
			titles[i] = t
		} else {
			titles[i] = "For " + s
		}
	}
	if prompt == "" {
		prompt = fmt.Sprintf("Allow %s/%s?", in.Resource.Server, in.Resource.Name)
	}
	args, _ := json.MarshalIndent(in.Args, "", "  ")
	return ElicitParams{
		Message: fmt.Sprintf("[mcp-gateway] %s\n\nServer: %s\nTool: %s\nArguments:\n%s",
			prompt, in.Resource.Server, in.Resource.Name, args),
		RequestedSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"scope": map[string]any{
					"type":        "string",
					"title":       "Approve",
					"description": "Choose how long this approval lasts. Decline to deny the call.",
					"enum":        scopes,
					"enumNames":   titles,
				},
			},
			"required": []string{"scope"},
		},
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
