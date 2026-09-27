package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Grant lifetimes.
const (
	OnceTTL    = time.Minute
	SessionTTL = 8 * time.Hour
	// MaxGrantTTL bounds duration scopes offered by policy ("24h", ...).
	MaxGrantTTL = 30 * 24 * time.Hour
)

// Errors.
var (
	// ErrNoChannel means no approval channel usable for this request is
	// available; the request must be denied.
	ErrNoChannel = errors.New("broker: no usable approval channel")
	ErrNotFound  = errors.New("broker: no such approval")
	ErrForbidden = errors.New("broker: not allowed to approve this request")
	ErrBadScope  = errors.New("broker: scope not offered")
)

// ElicitParams are the params of a form-mode elicitation/create request.
type ElicitParams struct {
	Message         string         `json:"message"`
	RequestedSchema map[string]any `json:"requestedSchema"`
}

// URLElicitParams are the params of a URL-mode elicitation/create request
// (MCP 2025-11-25): the client offers the user to open URL; the result
// only says whether they agreed, the decision happens on that page.
type URLElicitParams struct {
	Mode          string `json:"mode"`
	Message       string `json:"message"`
	URL           string `json:"url"`
	ElicitationID string `json:"elicitationId"`
}

// ElicitResult is the result of an elicitation/create request.
type ElicitResult struct {
	// Action is "accept", "decline" or "cancel".
	Action  string         `json:"action"`
	Content map[string]any `json:"content,omitempty"`
}

// Elicitor is the client side of a session, as seen by the broker.
type Elicitor interface {
	// SupportsForm and SupportsURL report the elicitation modes the
	// client declared.
	SupportsForm() bool
	SupportsURL() bool
	// Elicit sends elicitation/create with params (ElicitParams or
	// URLElicitParams) and waits for the result.
	Elicit(ctx context.Context, params any) (ElicitResult, error)
	// Notify sends a notification to the client.
	Notify(method string, params any)
}

// Options configure a Broker.
type Options struct {
	// Timeout bounds how long a request waits for a human decision.
	Timeout time.Duration
	// GrantsFile persists duration grants ("" = memory only).
	GrantsFile string
	// URLTemplate is the approval page URL with "{id}" for the approval
	// id; empty disables the url channel.
	URLTemplate string
	// OOB enables out-of-band approvals (the control API is serving).
	OOB bool
	// AdminGroup members may approve any request and see all grants.
	AdminGroup string
	Log        *slog.Logger
}

// Broker obtains approvals and keeps grants.
type Broker struct {
	opts  Options
	now   func() time.Time
	store *Store
	log   *slog.Logger

	mu      sync.Mutex
	pending map[string]*Pending
}

// Pending is an approval waiting for a human decision.
type Pending struct {
	ID        string              `json:"id"`
	Channel   pep.Channel         `json:"channel"`
	Principal principal.Principal `json:"principal"`
	Action    string              `json:"action"`
	Server    string              `json:"server"`
	Name      string              `json:"name"`
	Args      map[string]any      `json:"args,omitempty"`
	Prompt    string              `json:"prompt"`
	Scopes    []string            `json:"scopes"`
	Created   time.Time           `json:"created"`
	Expires   time.Time           `json:"expires"`

	result chan *pep.Grant // nil grant: denied
}

// Approver is a human deciding on approvals (through the control API).
type Approver struct {
	Name   string   `json:"name"`
	UID    uint32   `json:"uid"`
	Groups []string `json:"groups"`
}

// New returns a broker.
func New(opts Options) (*Broker, error) {
	log := opts.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	b := &Broker{opts: opts, now: time.Now, log: log, pending: map[string]*Pending{}}
	store, err := OpenStore(opts.GrantsFile, func() time.Time { return b.now() })
	if err != nil {
		return nil, err
	}
	b.store = store
	return b, nil
}

// Grants returns the principal's unexpired grants for server/tool.
func (b *Broker) Grants(p principal.Principal, server, tool string) []pep.Grant {
	return b.store.Match(p, server, tool)
}

// EndSession drops the session grants of a session.
func (b *Broker) EndSession(sessionID string) { b.store.EndSession(sessionID) }

// Approve asks a human to approve the request described by in, through
// the policy's channel or its fallback. It returns the resulting grant, or
// nil if the request was declined. A "once" grant is returned but not
// stored, so it is consumed by the single re-evaluation that uses it.
func (b *Broker) Approve(ctx context.Context, el Elicitor, in pep.Input, ask pep.AskSpec) (*pep.Grant, error) {
	if len(ask.Scopes) == 0 {
		ask.Scopes = []string{"once"}
	}
	ctx, cancel := context.WithTimeout(ctx, b.opts.Timeout)
	defer cancel()
	for _, c := range []string{string(ask.Channel), ask.Fallback} {
		switch pep.Channel(c) {
		case pep.ChannelForm:
			if el.SupportsForm() {
				return b.viaForm(ctx, el, in, ask)
			}
		case pep.ChannelURL:
			if b.opts.URLTemplate != "" && el.SupportsURL() {
				return b.viaURL(ctx, el, in, ask)
			}
		case pep.ChannelOOB:
			if b.opts.OOB {
				return b.viaOOB(ctx, el, in, ask)
			}
		}
	}
	return nil, ErrNoChannel
}

// --- form ---------------------------------------------------------------

func (b *Broker) viaForm(ctx context.Context, el Elicitor, in pep.Input, ask pep.AskSpec) (*pep.Grant, error) {
	res, err := el.Elicit(ctx, formParams(in, ask.Prompt, ask.Scopes))
	if err != nil {
		return nil, fmt.Errorf("broker: elicitation failed: %w", err)
	}
	if res.Action != "accept" {
		return nil, nil
	}
	scope, _ := res.Content["scope"].(string)
	// With form mode the governed client answers itself; the approval is
	// recorded as the principal's own.
	return b.grant(in.Principal, in.Resource.Server, in.Resource.Name, scope, ask.Scopes, in.Principal.Sub, pep.ChannelForm)
}

var scopeTitles = map[string]string{
	"once":    "Only this call",
	"session": "For this session",
}

func scopeTitle(s string) string {
	if t, ok := scopeTitles[s]; ok {
		return t
	}
	return "For " + s
}

func describe(in pep.Input, prompt string) string {
	if prompt == "" {
		prompt = fmt.Sprintf("Allow %s/%s?", in.Resource.Server, in.Resource.Name)
	}
	args, _ := json.MarshalIndent(in.Args, "", "  ")
	return fmt.Sprintf("[mcp-gateway] %s\n\nServer: %s\nTool: %s\nArguments:\n%s",
		prompt, in.Resource.Server, in.Resource.Name, args)
}

func formParams(in pep.Input, prompt string, scopes []string) ElicitParams {
	titles := make([]string, len(scopes))
	for i, s := range scopes {
		titles[i] = scopeTitle(s)
	}
	return ElicitParams{
		Message: describe(in, prompt),
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

// --- url and out-of-band ------------------------------------------------

func (b *Broker) approvalURL(id string) string {
	return strings.ReplaceAll(b.opts.URLTemplate, "{id}", id)
}

func (b *Broker) viaURL(ctx context.Context, el Elicitor, in pep.Input, ask pep.AskSpec) (*pep.Grant, error) {
	p := b.addPending(in, ask, pep.ChannelURL)
	defer b.dropPending(p.ID)
	defer el.Notify("notifications/elicitation/complete", map[string]any{"elicitationId": p.ID})

	type elicited struct {
		res ElicitResult
		err error
	}
	opened := make(chan elicited, 1)
	go func() {
		res, err := el.Elicit(ctx, URLElicitParams{
			Mode:          "url",
			Message:       describe(in, ask.Prompt) + "\n\nOpen the approval page to decide.",
			URL:           b.approvalURL(p.ID),
			ElicitationID: p.ID,
		})
		opened <- elicited{res, err}
	}()
	for {
		select {
		case g := <-p.result:
			return g, nil
		case e := <-opened:
			if e.err != nil {
				return nil, fmt.Errorf("broker: elicitation failed: %w", e.err)
			}
			if e.res.Action != "accept" {
				return nil, nil // the user declined to open the page
			}
			opened = nil // keep waiting for the decision on the page
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (b *Broker) viaOOB(ctx context.Context, el Elicitor, in pep.Input, ask pep.AskSpec) (*pep.Grant, error) {
	p := b.addPending(in, ask, pep.ChannelOOB)
	defer b.dropPending(p.ID)
	where := "on the mcp-gateway approvals page"
	if b.opts.URLTemplate != "" {
		where = "at " + b.approvalURL(p.ID)
	}
	el.Notify("notifications/message", map[string]any{
		"level":  "notice",
		"logger": "mcp-gateway",
		"data":   fmt.Sprintf("Waiting for approval of %s/%s %s (id %s).", in.Resource.Server, in.Resource.Name, where, p.ID),
	})
	select {
	case g := <-p.result:
		return g, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (b *Broker) addPending(in pep.Input, ask pep.AskSpec, c pep.Channel) *Pending {
	now := b.now()
	p := &Pending{
		ID:        "a-" + randomHex(16),
		Channel:   c,
		Principal: in.Principal,
		Action:    in.Action,
		Server:    in.Resource.Server,
		Name:      in.Resource.Name,
		Args:      in.Args,
		Prompt:    ask.Prompt,
		Scopes:    ask.Scopes,
		Created:   now,
		Expires:   now.Add(b.opts.Timeout),
		result:    make(chan *pep.Grant, 1),
	}
	b.mu.Lock()
	b.pending[p.ID] = p
	b.mu.Unlock()
	b.log.Info("approval pending", "id", p.ID, "channel", c, "sub", p.Principal.Sub, "server", p.Server, "name", p.Name)
	return p
}

func (b *Broker) dropPending(id string) {
	b.mu.Lock()
	delete(b.pending, id)
	b.mu.Unlock()
}

// isAdmin reports whether a may act on everyone's approvals and grants.
func (b *Broker) isAdmin(a Approver) bool {
	return a.UID == 0 || (b.opts.AdminGroup != "" && slices.Contains(a.Groups, b.opts.AdminGroup))
}

// mayApprove: the principal themself (same local account) or an admin.
func (b *Broker) mayApprove(a Approver, p *Pending) bool {
	if b.isAdmin(a) {
		return true
	}
	return p.Principal.UID != nil && *p.Principal.UID == a.UID
}

// ListPending returns the pending approvals a may decide on.
func (b *Broker) ListPending(a Approver) []Pending {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []Pending{}
	for _, p := range b.pending {
		if b.mayApprove(a, p) {
			out = append(out, *p)
		}
	}
	slices.SortFunc(out, func(x, y Pending) int { return x.Created.Compare(y.Created) })
	return out
}

// GetPending returns one pending approval if a may decide on it.
func (b *Broker) GetPending(a Approver, id string) (Pending, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.pending[id]
	if !ok || !b.mayApprove(a, p) {
		return Pending{}, ErrNotFound
	}
	return *p, nil
}

// Resolve records a's decision on approval id. On approval it returns the
// grant for scope, which must be one the policy offered.
func (b *Broker) Resolve(a Approver, id string, approve bool, scope string) (*pep.Grant, error) {
	b.mu.Lock()
	p, ok := b.pending[id]
	if !ok || !b.mayApprove(a, p) {
		b.mu.Unlock()
		// Someone else's approval is reported as unknown.
		return nil, ErrNotFound
	}
	if approve && !slices.Contains(p.Scopes, scope) {
		b.mu.Unlock()
		return nil, ErrBadScope
	}
	delete(b.pending, id)
	b.mu.Unlock()

	var g *pep.Grant
	if approve {
		var err error
		g, err = b.grant(p.Principal, p.Server, p.Name, scope, p.Scopes, a.Name, p.Channel)
		if err != nil {
			p.result <- nil
			return nil, err
		}
	}
	b.log.Info("approval resolved", "id", id, "approved", approve, "by", a.Name, "scope", scope)
	p.result <- g
	return g, nil
}

// grant creates (and, unless "once", stores) a grant.
func (b *Broker) grant(p principal.Principal, server, tool, scope string, offered []string, by string, c pep.Channel) (*pep.Grant, error) {
	if !slices.Contains(offered, scope) {
		return nil, fmt.Errorf("%w: %q", ErrBadScope, scope)
	}
	ttl, stored := OnceTTL, scope
	switch scope {
	case "once":
	case "session":
		ttl = SessionTTL
	default:
		d, err := time.ParseDuration(scope)
		if err != nil || d <= 0 || d > MaxGrantTTL {
			return nil, fmt.Errorf("%w: %q", ErrBadScope, scope)
		}
		ttl, stored = d, "duration"
	}
	g := &pep.Grant{
		ID:         "g-" + randomHex(8),
		Sub:        p.Sub,
		Issuer:     p.Issuer,
		Server:     server,
		Tool:       tool,
		Scope:      stored,
		SessionID:  p.SessionID,
		Expires:    b.now().Add(ttl).UTC().Format(time.RFC3339),
		ApprovedBy: by,
		Channel:    c,
	}
	if scope != "once" {
		if err := b.store.Add(*g); err != nil {
			return nil, fmt.Errorf("broker: storing grant: %w", err)
		}
	}
	return g, nil
}

// ListGrants returns the grants a may see: their own, or all for admins.
func (b *Broker) ListGrants(a Approver) []pep.Grant {
	out := []pep.Grant{}
	for _, g := range b.store.List() {
		if b.isAdmin(a) || g.Sub == a.Name {
			out = append(out, g)
		}
	}
	return out
}

// RevokeGrant removes a grant a may see.
func (b *Broker) RevokeGrant(a Approver, id string) error {
	g, ok := b.store.Get(id)
	if !ok || (!b.isAdmin(a) && g.Sub != a.Name) {
		return ErrNotFound
	}
	b.log.Info("grant revoked", "id", id, "by", a.Name)
	return b.store.Revoke(id)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
