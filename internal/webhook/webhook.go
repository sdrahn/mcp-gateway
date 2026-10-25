// Package webhook posts pending approvals to configured receivers (chat
// bots, ticket systems, a central inbox for many gateways) and takes
// their decisions back on a signed callback (docs/architecture.md,
// section 11, step 39 stage E; D21).
//
// Every request either way is signed with the webhook's secret: the
// header X-MCP-Gateway-Signature is "t=<unix time>,v1=<hex HMAC-SHA256
// of "<t>.<body>">". The gateway takes a callback only with a valid
// signature at most five minutes old, and only once. The callback names
// who decided; the receiver vouches for that person as an identity
// provider does for a sign-in, and the approver rules decide whether
// they may.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/pep"
)

// SignatureHeader carries a request's signature; EventHeader the kind of
// a post.
const (
	SignatureHeader = "X-MCP-Gateway-Signature"
	EventHeader     = "X-MCP-Gateway-Event"
	// Via is how decisions taken on a callback are audited.
	Via = "webhook"
	// maxSkew is how old (or how far ahead) a signed callback may be;
	// replays within it are refused by its signature.
	maxSkew      = 5 * time.Minute
	postTimeout  = 10 * time.Second
	postAttempts = 3
	maxReplays   = 100000
)

// firstRetry is the wait before the second attempt of a post (then four
// times as long); a variable for the tests.
var firstRetry = time.Second

// Hook is one receiver.
type Hook struct {
	Name string
	URL  string
	// Secret signs posts and authenticates callbacks.
	Secret []byte
	// IncludeArgs sends the call's arguments; Servers, if any, limits
	// the posts to those servers' approvals.
	IncludeArgs bool
	Servers     []string
	// LocalAccounts lets callbacks name local accounts ("user:<name>"),
	// which the approver rules then treat as that account (never root);
	// without it a callback names remote approvers only.
	LocalAccounts bool
}

// Sign returns the signature header value of body at t.
func Sign(secret, body []byte, t time.Time) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	return "t=" + ts + ",v1=" + mac(secret, ts, body)
}

func mac(secret []byte, ts string, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts))
	m.Write([]byte("."))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// Verify checks a signature header value for body at now; it returns the
// signature (for replay protection) or why it fails.
func Verify(secret, body []byte, header string, now time.Time) (string, error) {
	var ts, sig string
	for _, part := range strings.Split(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sig = v
		}
	}
	if ts == "" || sig == "" {
		return "", errors.New("not signed (" + SignatureHeader + ": t=...,v1=...)")
	}
	t, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return "", errors.New("bad timestamp")
	}
	if d := now.Sub(time.Unix(t, 0)); d > maxSkew || d < -maxSkew {
		return "", fmt.Errorf("signed %s ago, more than %s", d.Round(time.Second), maxSkew)
	}
	if !hmac.Equal([]byte(sig), []byte(mac(secret, ts, body))) {
		return "", errors.New("the signature does not match")
	}
	return sig, nil
}

// Broker is what the webhooks decide with (broker.Broker).
type Broker interface {
	Subscribe() (<-chan broker.Event, func())
	ApprovalURL(id string) string
	ResolveVia(ctx context.Context, a broker.Approver, id string, approve bool, scope, via string) (*pep.Grant, error)
}

// Auditor records callbacks (audit.Logger).
type Auditor interface {
	Event(op string, ok bool, fields map[string]string)
}

// Hooks posts the approvals and serves the callbacks.
type Hooks struct {
	Hooks  []Hook
	Broker Broker
	// Callback is the URL a receiver sends a decision to, with {name}
	// for the webhook's name; empty: posts only (no HTTPS listener).
	Callback string
	// Gateway names this gateway in the posts (its host).
	Gateway string
	Client  *http.Client
	Audit   Auditor
	Log     *slog.Logger

	now func() time.Time
	// lookupUser finds a local account (NSS), for "user:" approvers.
	lookupUser func(name string) (broker.Approver, error)

	mu   sync.Mutex
	seen map[string]time.Time // signatures of callbacks taken, by when they lapse
}

func (h *Hooks) init() {
	if h.now == nil {
		h.now = time.Now
	}
	if h.Log == nil {
		h.Log = slog.New(slog.DiscardHandler)
	}
	if h.Client == nil {
		h.Client = &http.Client{Timeout: postTimeout}
	}
	if h.lookupUser == nil {
		h.lookupUser = localApprover
	}
}

// Event is a post's body.
type Event struct {
	Type    string `json:"type"` // "pending", "resolved", "ping"
	Gateway string `json:"gateway"`
	ID      string `json:"id,omitempty"`
	New     bool   `json:"new,omitempty"`
	Call    *Call  `json:"call,omitempty"`
	URL     string `json:"url,omitempty"` // the approval page
	// Callback is where a decision goes, signed as the post is.
	Callback string    `json:"callback,omitempty"`
	Time     time.Time `json:"time"`
}

// Call is what the post tells of the pending approval.
type Call struct {
	Server    string         `json:"server"`
	Tool      string         `json:"tool"`
	Action    string         `json:"action"`
	Principal string         `json:"principal"`
	Issuer    string         `json:"issuer,omitempty"`
	Client    string         `json:"client,omitempty"` // as the agent names itself
	Scopes    []string       `json:"scopes"`
	Created   time.Time      `json:"created"`
	Expires   time.Time      `json:"expires"`
	Waiting   bool           `json:"waiting"`
	Args      map[string]any `json:"args,omitempty"` // with include_args only
}

// Run posts the broker's approval events until ctx ends: each new
// pending approval, and each decided or expired one that was posted.
func (h *Hooks) Run(ctx context.Context) {
	h.init()
	ch, stop := h.Broker.Subscribe()
	defer stop()
	posted := map[string]map[string]bool{} // approval id → hooks posted to
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-ch:
			switch {
			case ev.Type == "pending" && ev.New && ev.Pending != nil:
				for i := range h.Hooks {
					hk := &h.Hooks[i]
					if !hk.wants(ev.Pending.Server) {
						continue
					}
					if posted[ev.ID] == nil {
						posted[ev.ID] = map[string]bool{}
					}
					posted[ev.ID][hk.Name] = true
					go h.post(ctx, hk, h.pendingEvent(hk, ev))
				}
			case ev.Type == "resolved" && posted[ev.ID] != nil:
				for i := range h.Hooks {
					hk := &h.Hooks[i]
					if posted[ev.ID][hk.Name] {
						go h.post(ctx, hk, Event{Type: "resolved", Gateway: h.Gateway, ID: ev.ID, Time: h.now()})
					}
				}
				delete(posted, ev.ID)
			}
		}
	}
}

func (hk *Hook) wants(server string) bool {
	if len(hk.Servers) == 0 {
		return true
	}
	for _, s := range hk.Servers {
		if s == server {
			return true
		}
	}
	return false
}

func (h *Hooks) pendingEvent(hk *Hook, ev broker.Event) Event {
	p := ev.Pending
	c := &Call{Server: p.Server, Tool: p.Name, Action: p.Action, Principal: p.Principal.Sub, Issuer: p.Principal.Issuer,
		Client: strings.TrimSpace(p.Principal.Client.Name + " " + p.Principal.Client.Version), Scopes: p.Scopes,
		Created: p.Created, Expires: p.Expires, Waiting: p.Waiting}
	if hk.IncludeArgs {
		c.Args = p.Args
	}
	e := Event{Type: "pending", Gateway: h.Gateway, ID: ev.ID, New: true, Call: c, URL: h.Broker.ApprovalURL(ev.ID), Time: h.now()}
	if h.Callback != "" {
		e.Callback = strings.ReplaceAll(h.Callback, "{name}", hk.Name)
	}
	return e
}

// post sends ev to hk, signed, trying again after failures.
func (h *Hooks) post(ctx context.Context, hk *Hook, ev Event) {
	if err := h.Send(ctx, hk, ev); err != nil {
		h.Log.Warn("webhook: posting failed", "webhook", hk.Name, "id", ev.ID, "type", ev.Type, "err", err)
	}
}

// Send posts ev to hk, signed; it tries postAttempts times, waiting
// longer each time, and returns the last error.
func (h *Hooks) Send(ctx context.Context, hk *Hook, ev Event) error {
	h.init()
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	wait := firstRetry
	for attempt := 1; ; attempt++ {
		err = h.sendOnce(ctx, hk, ev.Type, body)
		if err == nil || attempt == postAttempts {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		wait *= 4
	}
}

// Ping posts a signed "ping" event to hk once (the doctor's check).
func (h *Hooks) Ping(ctx context.Context, hk *Hook) error {
	h.init()
	body, err := json.Marshal(Event{Type: "ping", Gateway: h.Gateway, Time: h.now()})
	if err != nil {
		return err
	}
	return h.sendOnce(ctx, hk, "ping", body)
}

func (h *Hooks) sendOnce(ctx context.Context, hk *Hook, kind string, body []byte) error {
	ctx, cancel := context.WithTimeout(ctx, postTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hk.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(EventHeader, kind)
	req.Header.Set(SignatureHeader, Sign(hk.Secret, body, h.now()))
	resp, err := h.Client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s answered %s", hk.URL, resp.Status)
	}
	return nil
}

// Decision is a callback's body.
type Decision struct {
	ID       string `json:"id"`
	Decision string `json:"decision"` // "approve" or "deny"
	Scope    string `json:"scope,omitempty"`
	// Approver is who decided, as the approver rules name them:
	// "user:<local account>" or "remote-user:<subject>" (then Groups are
	// theirs, for remote-group: rules).
	Approver string   `json:"approver"`
	Groups   []string `json:"groups,omitempty"`
}

// Handler serves POST /approvals/webhook/{name}.
func (h *Hooks) Handler() http.Handler {
	h.init()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /approvals/webhook/{name}", h.callback)
	return mux
}

func (h *Hooks) hook(name string) *Hook {
	for i := range h.Hooks {
		if h.Hooks[i].Name == name {
			return &h.Hooks[i]
		}
	}
	return nil
}

func (h *Hooks) callback(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	hk := h.hook(name)
	if hk == nil {
		writeError(w, http.StatusNotFound, "no such webhook")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil {
		writeError(w, http.StatusBadRequest, "body too large")
		return
	}
	refuse := func(status int, msg, approver, id string) {
		h.audit(false, name, approver, id, msg)
		h.Log.Warn("webhook: callback refused", "webhook", name, "approver", approver, "id", id, "reason", msg)
		writeError(w, status, msg)
	}
	sig, err := Verify(hk.Secret, body, r.Header.Get(SignatureHeader), h.now())
	if err != nil {
		// Not audited: anyone reaching the listener could fill the audit
		// trail. What a receiver signed is.
		h.Log.Debug("webhook: callback without a valid signature", "webhook", name, "reason", err)
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if !h.firstUse(name+":"+sig, h.now().Add(2*maxSkew)) {
		refuse(http.StatusConflict, "replayed: this callback was taken before", "", "")
		return
	}
	var d Decision
	if err := json.Unmarshal(body, &d); err != nil || d.ID == "" {
		refuse(http.StatusBadRequest, "invalid body", "", "")
		return
	}
	if d.Decision != "approve" && d.Decision != "deny" {
		refuse(http.StatusBadRequest, `decision must be "approve" or "deny"`, d.Approver, d.ID)
		return
	}
	a, err := h.approver(hk, d)
	if err != nil {
		refuse(http.StatusBadRequest, err.Error(), d.Approver, d.ID)
		return
	}
	g, err := h.Broker.ResolveVia(r.Context(), a, d.ID, d.Decision == "approve", d.Scope, Via)
	switch {
	case errors.Is(err, broker.ErrNotFound), errors.Is(err, broker.ErrForbidden):
		refuse(http.StatusNotFound, "no such approval, or "+d.Approver+" may not decide it", d.Approver, d.ID)
	case errors.Is(err, broker.ErrBadScope):
		refuse(http.StatusBadRequest, "scope not offered", d.Approver, d.ID)
	case err != nil:
		refuse(http.StatusInternalServerError, "internal error", d.Approver, d.ID)
	default:
		h.audit(true, name, d.Approver, d.ID, "")
		if g == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(g)
	}
}

// approver is who a callback names: a local account (never root, as for
// the approval page) or a remote approver without one.
func (h *Hooks) approver(hk *Hook, d Decision) (broker.Approver, error) {
	issuer := "webhook:" + hk.Name
	if name, ok := strings.CutPrefix(d.Approver, "user:"); ok && name != "" {
		if !hk.LocalAccounts {
			return broker.Approver{}, fmt.Errorf("approver %s: this webhook may not name local accounts (local_accounts)", d.Approver)
		}
		a, err := h.lookupUser(name)
		if err != nil {
			return broker.Approver{}, fmt.Errorf("approver %s: no such local account", d.Approver)
		}
		a.Remote, a.Issuer = true, issuer
		return a, nil
	}
	if sub, ok := strings.CutPrefix(d.Approver, "remote-user:"); ok && sub != "" {
		return broker.Approver{Name: sub, Groups: d.Groups, Remote: true, Issuer: issuer, NoUID: true}, nil
	}
	return broker.Approver{}, errors.New(`approver must be "user:<account>" or "remote-user:<subject>"`)
}

func localApprover(name string) (broker.Approver, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return broker.Approver{}, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return broker.Approver{}, err
	}
	a := broker.Approver{Name: u.Username, UID: uint32(uid)}
	if gids, err := u.GroupIds(); err == nil {
		for _, gid := range gids {
			if g, err := user.LookupGroupId(gid); err == nil {
				a.Groups = append(a.Groups, g.Name)
			}
		}
	}
	return a, nil
}

// firstUse records key until lapse; false if it was recorded before.
func (h *Hooks) firstUse(key string, lapse time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	if h.seen == nil {
		h.seen = map[string]time.Time{}
	}
	if len(h.seen) >= maxReplays {
		for k, t := range h.seen {
			if now.After(t) {
				delete(h.seen, k)
			}
		}
	}
	if t, ok := h.seen[key]; ok && now.Before(t) {
		return false
	}
	h.seen[key] = lapse
	return true
}

func (h *Hooks) audit(ok bool, hook, approver, id, reason string) {
	if h.Audit == nil {
		return
	}
	f := map[string]string{"webhook": hook, "approver": approver, "id": id}
	if reason != "" {
		f["reason"] = reason
	}
	h.Audit.Event("mcp-webhook-callback", ok, f)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
