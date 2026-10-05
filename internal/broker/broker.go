package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/metrics"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Grant lifetimes.
const (
	OnceTTL    = time.Minute
	SessionTTL = 8 * time.Hour
	// MaxGrantTTL bounds duration scopes offered by policy ("24h", ...).
	MaxGrantTTL = 30 * 24 * time.Hour
	// OrphanOnceTTL is how long a "once" grant from an approval decided
	// while no call was waiting stays usable: the agent's next attempt
	// takes it.
	OrphanOnceTTL = 15 * time.Minute
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
	// PendingFile persists pending url and oob approvals, so they survive
	// the waiting call and restarts ("" = memory only).
	PendingFile string
	// URLTemplate is the approval page URL with "{id}" for the approval
	// id; empty disables the url channel.
	URLTemplate string
	// OOB enables out-of-band approvals (the control API is serving).
	OOB bool
	// Policy decides who may decide on approvals and manage grants
	// (data.mcp.approvals); nil allows only the principal themself.
	Policy BoolPolicy
	// Audit, if set, records approval decisions and grant revocations.
	Audit *audit.Logger
	Log   *slog.Logger
}

// BoolPolicy answers boolean policy queries (pep.OPA implements it).
type BoolPolicy interface {
	Bool(ctx context.Context, path string, input any) (bool, error)
}

// Policy paths for approver decisions.
const (
	approvePath        = "/v1/data/mcp/approvals/allow"
	manageGrantPath    = "/v1/data/mcp/approvals/manage_grant"
	manageInstancePath = "/v1/data/mcp/approvals/manage_instance"
	manageSignInPath   = "/v1/data/mcp/approvals/manage_sign_in"
	reviewPolicyPath   = "/v1/data/mcp/approvals/review_policy"
)

// Broker obtains approvals and keeps grants.
type Broker struct {
	opts Options
	// live holds the options a configuration reload changes (Timeout,
	// URLTemplate); see SetApprovals.
	live  atomic.Pointer[liveOptions]
	now   func() time.Time
	store *Store
	log   *slog.Logger

	mu      sync.Mutex
	pending map[string]*Pending
	subs    map[chan Event]struct{}
}

// Event is a change of the pending approvals, for subscribers (the control
// API's event stream, e-mail notifications).
type Event struct {
	// Type is "pending" (an approval appeared, was taken over by a new
	// attempt, or lost its waiting call) or "resolved" (decided, timed
	// out, declined, expired).
	Type string `json:"type"`
	ID   string `json:"id"`
	// New marks the first announcement of an approval.
	New     bool     `json:"new,omitempty"`
	Pending *Pending `json:"pending,omitempty"` // a copy, for "pending"
}

// Subscribe returns a channel of pending approval events and a function
// ending the subscription. Events that a slow subscriber does not take in
// time are dropped.
func (b *Broker) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	b.mu.Lock()
	if b.subs == nil {
		b.subs = map[chan Event]struct{}{}
	}
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, ch)
			b.mu.Unlock()
		})
	}
}

// publish sends ev to the subscribers. Caller holds b.mu.
func (b *Broker) publish(ev Event) {
	for ch := range b.subs {
		select {
		case ch <- ev:
		default:
			b.log.Warn("approval event dropped for a slow subscriber", "id", ev.ID)
		}
	}
}

// publishPending announces p. Caller holds b.mu.
func (b *Broker) publishPending(p *Pending, isNew bool) {
	c := *p
	b.publish(Event{Type: "pending", ID: p.ID, New: isNew, Pending: &c})
}

// ApprovalURL returns the approval page URL for id ("" without
// approvals.url_template).
func (b *Broker) ApprovalURL(id string) string {
	if b.urlTemplate() == "" {
		return ""
	}
	return b.approvalURL(id)
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
	// Waiting tells whether a call waits for the decision. An approval
	// whose call went away (the client left, the gateway restarted) stays
	// pending until it expires; deciding it stores the grant for the
	// agent's next attempt, which also picks up the approval itself if it
	// comes first.
	Waiting bool `json:"waiting"`

	result chan *pep.Grant // nil grant: denied; nil channel: no call waits
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
	b.live.Store(&liveOptions{timeout: opts.Timeout, urlTemplate: opts.URLTemplate})
	store, err := OpenStore(opts.GrantsFile, func() time.Time { return b.now() })
	if err != nil {
		return nil, err
	}
	b.store = store
	if err := b.loadPending(); err != nil {
		return nil, err
	}
	return b, nil
}

// liveOptions are the options a configuration reload changes.
type liveOptions struct {
	timeout     time.Duration
	urlTemplate string
}

// SetApprovals changes the approval timeout and the approval page's URL
// template (a reload of the configuration). Approvals already pending
// keep their expiry.
func (b *Broker) SetApprovals(timeout time.Duration, urlTemplate string) {
	b.live.Store(&liveOptions{timeout: timeout, urlTemplate: urlTemplate})
}

func (b *Broker) timeout() time.Duration { return b.live.Load().timeout }

func (b *Broker) urlTemplate() string { return b.live.Load().urlTemplate }

// loadPending restores the pending approvals of a previous run; no call
// waits for them any more.
func (b *Broker) loadPending() error {
	if b.opts.PendingFile == "" {
		return nil
	}
	data, err := os.ReadFile(b.opts.PendingFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var list []*Pending
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("broker: reading %s: %w", b.opts.PendingFile, err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range list {
		if p.ID == "" || !p.Expires.After(b.now()) {
			continue
		}
		orphan(p)
		b.pending[p.ID] = p
		b.log.Info("approval restored", "id", p.ID, "sub", p.Principal.Sub, "server", p.Server, "name", p.Name)
	}
	b.persistPending()
	return nil
}

// orphan marks p as having no waiting call. The session scope goes: the
// session that asked is gone.
func orphan(p *Pending) {
	p.result = nil
	p.Waiting = false
	p.Scopes = slices.DeleteFunc(slices.Clone(p.Scopes), func(s string) bool { return s == "session" })
	if len(p.Scopes) == 0 {
		p.Scopes = []string{"once"}
	}
}

// persistPending writes the pending approvals. Caller holds b.mu.
func (b *Broker) persistPending() {
	if b.opts.PendingFile == "" {
		return
	}
	list := make([]*Pending, 0, len(b.pending))
	for _, p := range b.pending {
		list = append(list, p)
	}
	slices.SortFunc(list, func(x, y *Pending) int { return x.Created.Compare(y.Created) })
	data, err := json.MarshalIndent(list, "", "  ")
	if err == nil {
		err = writeFileAtomic(b.opts.PendingFile, append(data, '\n'))
	}
	if err != nil {
		b.log.Warn("persisting pending approvals failed", "err", err)
	}
}

// pruneExpired drops orphaned approvals past their expiry (waiting ones
// end with their call). Caller holds b.mu.
func (b *Broker) pruneExpired() {
	changed := false
	for id, p := range b.pending {
		if p.result == nil && !p.Expires.After(b.now()) {
			delete(b.pending, id)
			b.publish(Event{Type: "resolved", ID: id})
			changed = true
		}
	}
	if changed {
		b.persistPending()
	}
}

// Grants returns the principal's unexpired grants for server/tool
// (without stored "once" grants; see TakeOnce).
func (b *Broker) Grants(p principal.Principal, server, tool string) []pep.Grant {
	return b.store.Match(p, server, tool)
}

// TakeOnce takes a stored "once" grant of p for server/tool (from an
// approval decided while no call was waiting). The caller consumes it
// with the call it allows, or gives it back with ReturnOnce.
func (b *Broker) TakeOnce(p principal.Principal, server, tool string) (pep.Grant, bool) {
	return b.store.TakeOnce(p, server, tool)
}

// ReturnOnce gives back a grant from TakeOnce that did not allow a call.
func (b *Broker) ReturnOnce(g pep.Grant) {
	if err := b.store.Add(g); err != nil {
		b.log.Warn("returning once grant failed", "grant", g.ID, "err", err)
	}
}

// EndSession drops the session grants of a session.
func (b *Broker) EndSession(sessionID string) { b.store.EndSession(sessionID) }

// Approve asks a human to approve the request described by in, through
// the policy's channel or its fallback. It returns the resulting grant, or
// nil if the request was declined. A "once" grant is returned but not
// stored, so it is consumed by the single re-evaluation that uses it.
func (b *Broker) Approve(ctx context.Context, el Elicitor, in pep.Input, ask pep.AskSpec) (*pep.Grant, error) {
	ask = withScopes(ask)
	c, err := b.Channel(el, ask)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, b.timeout())
	defer cancel()
	switch c {
	case pep.ChannelForm:
		return b.viaForm(ctx, el, in, ask)
	case pep.ChannelURL:
		return b.viaURL(ctx, el, in, ask)
	default:
		return b.viaOOB(ctx, el, in, ask)
	}
}

// Channel returns the channel an approval asked with ask takes for the
// client el: the policy's channel, else its fallback, whichever the
// client and the gateway's configuration make usable; ErrNoChannel if
// neither is.
func (b *Broker) Channel(el Elicitor, ask pep.AskSpec) (pep.Channel, error) {
	for _, c := range []pep.Channel{ask.Channel, pep.Channel(ask.Fallback)} {
		switch c {
		case pep.ChannelForm:
			if el.SupportsForm() {
				return c, nil
			}
		case pep.ChannelURL:
			if b.urlTemplate() != "" && el.SupportsURL() {
				return c, nil
			}
		case pep.ChannelOOB:
			if b.opts.OOB {
				return c, nil
			}
		}
	}
	return "", ErrNoChannel
}

// withScopes returns ask with its scopes, "once" if policy named none.
func withScopes(ask pep.AskSpec) pep.AskSpec {
	if len(ask.Scopes) == 0 {
		ask.Scopes = []string{"once"}
	}
	return ask
}

// --- form ---------------------------------------------------------------

func (b *Broker) viaForm(ctx context.Context, el Elicitor, in pep.Input, ask pep.AskSpec) (*pep.Grant, error) {
	res, err := el.Elicit(ctx, formParams(in, ask.Prompt, ask.Scopes))
	if err != nil {
		return nil, fmt.Errorf("broker: elicitation failed: %w", err)
	}
	return b.formAnswer(in, ask, res)
}

// formAnswer records the client's answer res to an approval form: the
// grant, nil if declined.
func (b *Broker) formAnswer(in pep.Input, ask pep.AskSpec, res ElicitResult) (*pep.Grant, error) {
	if res.Action != "accept" {
		b.auditApproval("", false, in.Principal, in.Resource.Server, in.Resource.Name, in.Principal.Sub, "", pep.ChannelForm)
		return nil, nil
	}
	scope, _ := res.Content["scope"].(string)
	// With form mode the governed client answers itself; the approval is
	// recorded as the principal's own.
	g, err := b.grant(in.Principal, in.Resource.Server, in.Resource.Name, scope, ask.Scopes, in.Principal.Sub, pep.ChannelForm)
	if err == nil {
		b.auditApproval(g.ID, true, in.Principal, in.Resource.Server, in.Resource.Name, in.Principal.Sub, scope, pep.ChannelForm)
	}
	return g, err
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
	return strings.ReplaceAll(b.urlTemplate(), "{id}", id)
}

func (b *Broker) viaURL(ctx context.Context, el Elicitor, in pep.Input, ask pep.AskSpec) (g *pep.Grant, err error) {
	p := b.addPending(in, ask, pep.ChannelURL, true)
	defer func() {
		b.endWait(p, err)
		if errors.Is(err, errDeclinedToOpen) {
			g, err = nil, nil // declined
		}
	}()
	defer el.Notify("notifications/elicitation/complete", map[string]any{"elicitationId": p.ID})

	type elicited struct {
		res ElicitResult
		err error
	}
	opened := make(chan elicited, 1)
	go func() {
		res, err := el.Elicit(ctx, b.urlParams(in, ask, p.ID))
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
				return nil, errDeclinedToOpen
			}
			opened = nil // keep waiting for the decision on the page
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (b *Broker) viaOOB(ctx context.Context, el Elicitor, in pep.Input, ask pep.AskSpec) (g *pep.Grant, err error) {
	p := b.addPending(in, ask, pep.ChannelOOB, true)
	defer func() { b.endWait(p, err) }()
	b.notifyOOB(el, in, p.ID)
	select {
	case g := <-p.result:
		return g, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// urlParams is the URL elicitation of approval id.
func (b *Broker) urlParams(in pep.Input, ask pep.AskSpec, id string) URLElicitParams {
	return URLElicitParams{
		Mode:          "url",
		Message:       describe(in, ask.Prompt) + "\n\nOpen the approval page to decide.",
		URL:           b.approvalURL(id),
		ElicitationID: id,
	}
}

// notifyOOB tells the client where approval id is decided.
func (b *Broker) notifyOOB(el Elicitor, in pep.Input, id string) {
	where := "on the mcp-gateway approvals page"
	if b.urlTemplate() != "" {
		where = "at " + b.approvalURL(id)
	}
	el.Notify("notifications/message", map[string]any{
		"level":  "notice",
		"logger": "mcp-gateway",
		"data":   fmt.Sprintf("Waiting for approval of %s/%s %s (id %s).", in.Resource.Server, in.Resource.Name, where, id),
	})
}

// addPending registers a pending approval for in, with a waiting call
// if waiting. An approval of the same request left without a waiting
// call (by an earlier attempt, possibly before a restart) is taken over
// instead, keeping its id, so an approval page opened for it stays
// valid.
func (b *Broker) addPending(in pep.Input, ask pep.AskSpec, c pep.Channel, waiting bool) *Pending {
	now := b.now()
	var result chan *pep.Grant
	if waiting {
		result = make(chan *pep.Grant, 1)
	}
	b.mu.Lock()
	b.pruneExpired()
	for _, p := range b.pending {
		if p.result == nil && sameRequest(p, in) {
			p.Principal, p.Scopes, p.Channel, p.Prompt = in.Principal, ask.Scopes, c, ask.Prompt
			p.Expires = now.Add(b.timeout())
			p.result = result
			p.Waiting = waiting
			b.persistPending()
			b.publishPending(p, false)
			b.mu.Unlock()
			b.log.Info("approval taken over by a new attempt", "id", p.ID, "sub", p.Principal.Sub, "server", p.Server, "name", p.Name)
			return p
		}
	}
	b.mu.Unlock()
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
		Expires:   now.Add(b.timeout()),
		Waiting:   waiting,
		result:    result,
	}
	b.mu.Lock()
	b.pending[p.ID] = p
	b.persistPending()
	b.publishPending(p, true)
	b.mu.Unlock()
	b.log.Info("approval pending", "id", p.ID, "channel", c, "sub", p.Principal.Sub, "server", p.Server, "name", p.Name)
	return p
}

// errDeclinedToOpen: the user did not open the URL-mode approval page.
var errDeclinedToOpen = errors.New("broker: approval page not opened")

// endWait ends the wait of the call for p: an approval decided, timed out
// or declined is gone; one whose call went away (the client left, the
// gateway shuts down) stays pending without a waiting call.
func (b *Broker) endWait(p *Pending, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pending[p.ID] != p {
		return // decided
	}
	if errors.Is(err, context.Canceled) && p.Expires.After(b.now()) {
		orphan(p)
		b.log.Info("approval kept without a waiting call", "id", p.ID)
		b.publishPending(p, false)
	} else {
		delete(b.pending, p.ID)
		b.publish(Event{Type: "resolved", ID: p.ID})
	}
	b.persistPending()
}

// sameRequest reports whether pending approval p is for the same request
// as in: principal (not session), target and arguments.
func sameRequest(p *Pending, in pep.Input) bool {
	a, b := p.Principal, in.Principal
	if a.Transport != b.Transport || a.Issuer != b.Issuer || a.Sub != b.Sub || !sameUID(a.UID, b.UID) ||
		p.Action != in.Action || p.Server != in.Resource.Server || p.Name != in.Resource.Name {
		return false
	}
	x, _ := json.Marshal(p.Args)
	y, _ := json.Marshal(in.Args)
	return string(x) == string(y)
}

func sameUID(a, b *uint32) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

// ApproverInput is the input of the approver rules (data.mcp.approvals):
// the approver and what they want to act on.
type ApproverInput struct {
	Approver *Approver       `json:"approver,omitempty"`
	Request  *ApprovalTarget `json:"request,omitempty"`
	Instance *InstanceTarget `json:"instance,omitempty"`
	Grant    *pep.Grant      `json:"grant,omitempty"`
	// SignIn is a principal's sign-in to a server (server and uid, as
	// for an instance).
	SignIn *InstanceTarget `json:"sign_in,omitempty"`
}

// ApprovalTarget is the call an approval is about, as approver rules see it.
type ApprovalTarget struct {
	Principal principal.Principal `json:"principal"`
	Server    string              `json:"server"`
	Name      string              `json:"name"`
	Action    string              `json:"action"`
}

// Target returns the call p is about.
func (p *Pending) Target() *ApprovalTarget {
	return &ApprovalTarget{Principal: p.Principal, Server: p.Server, Name: p.Name, Action: p.Action}
}

// InstanceTarget is a backend instance, as approver rules see it.
type InstanceTarget struct {
	Server string  `json:"server"`
	UID    *uint32 `json:"uid"`
}

// ask queries the approver policy; errors deny. Root may always act: it
// controls the host (and the policy) anyway.
func (b *Broker) ask(ctx context.Context, a Approver, path string, input ApproverInput) bool {
	if a.UID == 0 {
		return true
	}
	if b.opts.Policy == nil {
		return false
	}
	input.Approver = &a
	ok, err := b.opts.Policy.Bool(ctx, path, input)
	if err != nil {
		b.log.Warn("approver policy failed", "path", path, "err", err)
		return false
	}
	return ok
}

// mayApprove: as policy says; without policy, the principal themself.
// MayApprove reports whether a may decide on p.
func (b *Broker) MayApprove(ctx context.Context, a Approver, p Pending) bool {
	return b.mayApprove(ctx, a, &p)
}

func (b *Broker) mayApprove(ctx context.Context, a Approver, p *Pending) bool {
	if b.opts.Policy == nil && a.UID != 0 {
		return p.Principal.UID != nil && *p.Principal.UID == a.UID
	}
	return b.ask(ctx, a, approvePath, ApproverInput{Request: p.Target()})
}

// MayReviewPolicy reports whether a may see how a role data change would
// change decisions ("what changes?"), which shows every principal's
// access: as policy says; without policy, root only.
func (b *Broker) MayReviewPolicy(ctx context.Context, a Approver) bool {
	return b.ask(ctx, a, reviewPolicyPath, ApproverInput{})
}

// mayManage: as policy says; without policy, the principal's own grants.
// MayManageInstance reports whether a may see and stop a backend
// instance of server run for the principal with uid (nil: no local
// account). The same approver rules as for grants apply.
func (b *Broker) MayManageInstance(ctx context.Context, a Approver, server string, uid *uint32) bool {
	if b.opts.Policy == nil && a.UID != 0 {
		return uid != nil && *uid == a.UID
	}
	return b.ask(ctx, a, manageInstancePath, ApproverInput{Instance: &InstanceTarget{Server: server, UID: uid}})
}

// MayManageSignIn reports whether a may see and end the sign-in to server
// of the principal with uid (nil: no local account). The same approver
// rules as for instances apply.
func (b *Broker) MayManageSignIn(ctx context.Context, a Approver, server string, uid *uint32) bool {
	if b.opts.Policy == nil && a.UID != 0 {
		return uid != nil && *uid == a.UID
	}
	return b.ask(ctx, a, manageSignInPath, ApproverInput{SignIn: &InstanceTarget{Server: server, UID: uid}})
}

func (b *Broker) mayManage(ctx context.Context, a Approver, g pep.Grant) bool {
	if b.opts.Policy == nil && a.UID != 0 {
		return g.UID != nil && *g.UID == a.UID
	}
	return b.ask(ctx, a, manageGrantPath, ApproverInput{Grant: &g})
}

// snapshotPending copies the pending approvals.
func (b *Broker) snapshotPending() []Pending {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneExpired()
	out := make([]Pending, 0, len(b.pending))
	for _, p := range b.pending {
		out = append(out, *p)
	}
	return out
}

// PendingCount returns the number of pending approvals. It takes only the
// broker's lock, so the watchdog can use it to see that the broker is not
// stuck.
func (b *Broker) PendingCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}

// ListPending returns the pending approvals a may decide on.
func (b *Broker) ListPending(ctx context.Context, a Approver) []Pending {
	out := []Pending{}
	for _, p := range b.snapshotPending() {
		if b.mayApprove(ctx, a, &p) {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(x, y Pending) int { return x.Created.Compare(y.Created) })
	return out
}

// GetPending returns one pending approval if a may decide on it.
func (b *Broker) GetPending(ctx context.Context, a Approver, id string) (Pending, error) {
	b.mu.Lock()
	b.pruneExpired()
	p, ok := b.pending[id]
	var c Pending
	if ok {
		c = *p
	}
	b.mu.Unlock()
	if !ok || !b.mayApprove(ctx, a, &c) {
		return Pending{}, ErrNotFound
	}
	return c, nil
}

// Resolve records a's decision on approval id. On approval it returns the
// grant for scope, which must be one the policy offered.
func (b *Broker) Resolve(ctx context.Context, a Approver, id string, approve bool, scope string) (*pep.Grant, error) {
	b.mu.Lock()
	b.pruneExpired()
	p, ok := b.pending[id]
	var c Pending
	if ok {
		c = *p
	}
	b.mu.Unlock()
	// Someone else's approval is reported as unknown.
	if !ok || !b.mayApprove(ctx, a, &c) {
		return nil, ErrNotFound
	}
	b.mu.Lock()
	if b.pending[id] != p {
		b.mu.Unlock()
		return nil, ErrNotFound // decided or timed out meanwhile
	}
	// Re-read under the lock: a new attempt may have taken p over.
	c = *p
	if approve && !slices.Contains(c.Scopes, scope) {
		b.mu.Unlock()
		return nil, ErrBadScope
	}
	delete(b.pending, id)
	b.persistPending()
	b.publish(Event{Type: "resolved", ID: id})
	b.mu.Unlock()

	var g *pep.Grant
	if approve {
		var err error
		if c.result == nil {
			g, err = b.orphanGrant(c, scope, a.Name)
		} else {
			g, err = b.grant(c.Principal, c.Server, c.Name, scope, c.Scopes, a.Name, c.Channel)
		}
		if err != nil {
			if c.result != nil {
				c.result <- nil
			}
			return nil, err
		}
	}
	decision := "deny"
	if approve {
		decision = "approve"
	}
	metrics.ApprovalsDecided.Inc(decision)
	b.log.Info("approval resolved", "id", id, "approved", approve, "by", a.Name, "scope", scope, "waiting", c.result != nil)
	b.auditApproval(id, approve, c.Principal, c.Server, c.Name, a.Name, scope, c.Channel)
	if c.result != nil {
		c.result <- g
	}
	return g, nil
}

// orphanGrant stores the grant for an approval decided while no call was
// waiting: a "once" grant is kept for the next attempt (OrphanOnceTTL).
func (b *Broker) orphanGrant(p Pending, scope, by string) (*pep.Grant, error) {
	if scope != "once" {
		return b.grant(p.Principal, p.Server, p.Name, scope, p.Scopes, by, p.Channel)
	}
	g := pep.Grant{
		ID:         "g-" + randomHex(8),
		Sub:        p.Principal.Sub,
		Issuer:     p.Principal.Issuer,
		UID:        p.Principal.UID,
		Server:     p.Server,
		Tool:       p.Name,
		Scope:      "once",
		Expires:    b.now().Add(OrphanOnceTTL).UTC().Format(time.RFC3339),
		ApprovedBy: by,
		Channel:    p.Channel,
	}
	if err := b.store.Add(g); err != nil {
		return nil, fmt.Errorf("broker: storing grant: %w", err)
	}
	return &g, nil
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
		UID:        p.UID,
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

// ListGrants returns the grants a may see and revoke.
func (b *Broker) ListGrants(ctx context.Context, a Approver) []pep.Grant {
	out := []pep.Grant{}
	for _, g := range b.store.List() {
		if b.mayManage(ctx, a, g) {
			out = append(out, g)
		}
	}
	return out
}

// RevokeGrant removes a grant a may manage.
func (b *Broker) RevokeGrant(ctx context.Context, a Approver, id string) error {
	g, ok := b.store.Get(id)
	if !ok || !b.mayManage(ctx, a, g) {
		return ErrNotFound
	}
	b.log.Info("grant revoked", "id", id, "by", a.Name)
	b.opts.Audit.Event("mcp-grant-revoke", true, map[string]string{
		"id": id, "by": a.Name, "principal": g.Sub, "server": g.Server, "target": g.Tool,
	})
	return b.store.Revoke(id)
}

// auditApproval records an approval decision; declines are recorded as
// failed.
func (b *Broker) auditApproval(id string, approved bool, p principal.Principal, server, name, by, scope string, c pep.Channel) {
	if !approved {
		scope = ""
	}
	b.opts.Audit.Event("mcp-approval", approved, map[string]string{
		"id": id, "principal": p.Sub, "server": server, "target": name,
		"by": by, "scope": scope, "channel": string(c),
	})
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
