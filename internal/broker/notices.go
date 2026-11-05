package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Notices: what a trusted local service tells the approvers of a
// principal (a demotion of an agent's task category, say). A notice asks
// for no decision; its audience is the approvers of a request of the
// principal on its servers (approver rule allow), its mail goes to the
// notify rules' recipients as for such a request.
const (
	// NoticeTTL is how long a notice is listed.
	NoticeTTL = 7 * 24 * time.Hour
	// MaxNotices bounds the notices kept; the oldest go first.
	MaxNotices = 1000
	// MaxNoticeTitle and MaxNoticeText bound a notice's texts (bytes).
	MaxNoticeTitle = 200
	MaxNoticeText  = 4000
	// maxNoticeServers bounds the servers a notice names.
	maxNoticeServers = 32
)

// postNoticePath is the policy rule deciding who may post a notice.
const postNoticePath = "/v1/data/mcp/approvals/post_notice"

// ErrBadNotice means a notice to post is malformed (the error says how).
var ErrBadNotice = errors.New("broker: invalid notice")

// Notice severities.
const (
	SeverityInfo    = "info"
	SeverityWarning = "warning"
)

// Notice is a message to the approvers of a principal.
type Notice struct {
	ID string `json:"id"`
	// Principal is the principal the notice is about.
	Principal NoticePrincipal `json:"principal"`
	// Servers the notice is about; none: the principal's approvers by the
	// default rules.
	Servers  []string `json:"servers,omitempty"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Text     string   `json:"text"`
	// PostedBy is the account that posted it.
	PostedBy string    `json:"posted_by"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
}

// NoticePrincipal is a notice's principal: its name, and the uid of its
// local account if it has one (so that "self" applies).
type NoticePrincipal struct {
	Sub string  `json:"sub"`
	UID *uint32 `json:"uid,omitempty"`
}

// NoticeTarget is a notice as approver rules see it (input.notice).
type NoticeTarget struct {
	Principal string   `json:"principal"`
	Servers   []string `json:"servers"`
	Severity  string   `json:"severity"`
	Title     string   `json:"title"`
}

// storedNotice is a notice with the readers who dismissed it.
type storedNotice struct {
	Notice
	Dismissed []string `json:"dismissed,omitempty"`
}

func (n *Notice) target() *NoticeTarget {
	servers := n.Servers
	if servers == nil {
		servers = []string{}
	}
	return &NoticeTarget{Principal: n.Principal.Sub, Servers: servers, Severity: n.Severity, Title: n.Title}
}

// Requests are the requests a notice is "as for", one per server (one
// with no server if it names none): its audience may decide on one of
// them, its mail goes to the recipients of each.
func (n *Notice) Requests() []ApproverInput {
	servers := n.Servers
	if len(servers) == 0 {
		servers = []string{""}
	}
	var out []ApproverInput
	for _, s := range servers {
		out = append(out, ApproverInput{
			Request: &ApprovalTarget{Principal: principal.Principal{Sub: n.Principal.Sub, UID: n.Principal.UID},
				Server: s, Action: "notice", Servers: n.Servers},
			Notice: n.target(),
		})
	}
	return out
}

// checkNotice validates n and fills in its defaults.
func checkNotice(n *Notice) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrBadNotice, fmt.Sprintf(format, a...))
	}
	switch n.Severity {
	case "":
		n.Severity = SeverityInfo
	case SeverityInfo, SeverityWarning:
	default:
		return bad("severity must be %q or %q", SeverityInfo, SeverityWarning)
	}
	if n.Principal.Sub == "" || len(n.Principal.Sub) > 256 || !plainText(n.Principal.Sub, false) {
		return bad("principal is required (at most 256 bytes, one line)")
	}
	n.Title = strings.TrimSpace(n.Title)
	if n.Title == "" || len(n.Title) > MaxNoticeTitle || !plainText(n.Title, false) {
		return bad("title is required: one line of plain text, at most %d bytes", MaxNoticeTitle)
	}
	if len(n.Text) > MaxNoticeText || !plainText(n.Text, true) {
		return bad("text must be plain text of at most %d bytes", MaxNoticeText)
	}
	if len(n.Servers) > maxNoticeServers {
		return bad("at most %d servers", maxNoticeServers)
	}
	for _, s := range n.Servers {
		if s == "" || len(s) > 128 || !plainText(s, false) {
			return bad("invalid server name %q", s)
		}
	}
	return nil
}

// plainText reports whether s is valid UTF-8 without control characters
// (but line breaks and tabs where lines are allowed).
func plainText(s string, lines bool) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if lines && (r == '\n' || r == '\t') {
			continue
		}
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return false
		}
	}
	return true
}

// MayPostNotice reports whether a may post notices (approver rule
// post_notice; root always, others as policy says, without policy
// nobody else).
func (b *Broker) MayPostNotice(ctx context.Context, a Approver, n *Notice) bool {
	if a.Remote {
		return false
	}
	return b.ask(ctx, a, postNoticePath, ApproverInput{Notice: n.target()})
}

// PostNotice posts n as a, which must be allowed to (else ErrForbidden),
// and announces it. The id, times and poster are set here.
func (b *Broker) PostNotice(ctx context.Context, a Approver, n Notice) (Notice, error) {
	if err := checkNotice(&n); err != nil {
		return Notice{}, err
	}
	if !b.MayPostNotice(ctx, a, &n) {
		return Notice{}, ErrForbidden
	}
	n.Servers = slices.Compact(slices.Sorted(slices.Values(n.Servers)))
	n.ID = "n-" + randomHex(8)
	n.PostedBy = a.Name
	n.Created = b.now().UTC()
	n.Expires = n.Created.Add(NoticeTTL)
	b.mu.Lock()
	b.pruneNotices()
	if b.notices == nil {
		b.notices = map[string]*storedNotice{}
	}
	for len(b.notices) >= MaxNotices {
		b.dropOldestNotice()
	}
	b.notices[n.ID] = &storedNotice{Notice: n}
	b.persistNotices()
	c := n
	b.publish(Event{Type: "notice", ID: n.ID, New: true, Notice: &c})
	b.mu.Unlock()
	if b.opts.Audit != nil {
		b.opts.Audit.Event("mcp-notice", true, map[string]string{
			"id": n.ID, "by": a.Name, "principal": n.Principal.Sub, "servers": strings.Join(n.Servers, ","),
			"severity": n.Severity, "title": n.Title, "notify": strings.Join(b.noticeRecipients(ctx, &n), ","),
		})
	}
	b.log.Info("notice posted", "id", n.ID, "by", a.Name, "principal", n.Principal.Sub, "servers", n.Servers)
	return n, nil
}

// StringsPolicy answers set queries (pep.OPA implements it): the notify
// rules, for the audit of a notice.
type StringsPolicy interface {
	Strings(ctx context.Context, path string, input any) ([]string, error)
}

// NotifyPath is the policy rule naming whom to mail about a request.
const NotifyPath = "/v1/data/mcp/approvals/notify"

// noticeRecipients are the notify rules' names for n's requests, for the
// audit ("user:alice", "group:wheel"); none if the policy cannot say.
func (b *Broker) noticeRecipients(ctx context.Context, n *Notice) []string {
	sp, ok := b.opts.Policy.(StringsPolicy)
	if !ok {
		return nil
	}
	var names []string
	for _, in := range n.Requests() {
		got, err := sp.Strings(ctx, NotifyPath, in)
		if err != nil {
			continue
		}
		names = append(names, got...)
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// MayReadNotice reports whether a is in n's audience: may decide on a
// request of its principal on one of its servers (allow); without
// policy, the principal themself.
func (b *Broker) MayReadNotice(ctx context.Context, a Approver, n Notice) bool {
	if b.opts.Policy == nil && !a.Root() {
		return a.owns(n.Principal.UID)
	}
	for _, in := range n.Requests() {
		if b.ask(ctx, a, approvePath, in) {
			return true
		}
	}
	return false
}

// ReaderKey names a reader for dismissals: local accounts by name, those
// signed in on the page by issuer and subject.
func (a Approver) ReaderKey() string {
	if a.Remote {
		return "remote:" + a.Issuer + " " + a.Name
	}
	return a.Name
}

// ListNotices returns the unexpired notices a may read and has not
// dismissed, oldest first.
func (b *Broker) ListNotices(ctx context.Context, a Approver) []Notice {
	key := a.ReaderKey()
	b.mu.Lock()
	b.pruneNotices()
	var all []Notice
	for _, n := range b.notices {
		if !slices.Contains(n.Dismissed, key) {
			all = append(all, n.Notice)
		}
	}
	b.mu.Unlock()
	out := []Notice{}
	for _, n := range all {
		if b.MayReadNotice(ctx, a, n) {
			out = append(out, n)
		}
	}
	slices.SortFunc(out, func(x, y Notice) int { return x.Created.Compare(y.Created) })
	return out
}

// NoticeDismissed reports whether a dismissed notice id.
func (b *Broker) NoticeDismissed(a Approver, id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, ok := b.notices[id]
	return ok && slices.Contains(n.Dismissed, a.ReaderKey())
}

// DismissNotice hides notice id from a (only); ErrNotFound if a may not
// read it or it is gone.
func (b *Broker) DismissNotice(ctx context.Context, a Approver, id string) error {
	b.mu.Lock()
	b.pruneNotices()
	n, ok := b.notices[id]
	var c Notice
	if ok {
		c = n.Notice
	}
	b.mu.Unlock()
	if !ok || !b.MayReadNotice(ctx, a, c) {
		return ErrNotFound
	}
	key := a.ReaderKey()
	b.mu.Lock()
	defer b.mu.Unlock()
	if n, ok = b.notices[id]; !ok {
		return ErrNotFound
	}
	if !slices.Contains(n.Dismissed, key) {
		n.Dismissed = append(n.Dismissed, key)
		b.persistNotices()
	}
	b.publish(Event{Type: "notice-closed", ID: id, Reader: key})
	return nil
}

// pruneNotices drops expired notices. Caller holds b.mu.
func (b *Broker) pruneNotices() {
	changed := false
	for id, n := range b.notices {
		if !n.Expires.After(b.now()) {
			delete(b.notices, id)
			b.publish(Event{Type: "notice-closed", ID: id})
			changed = true
		}
	}
	if changed {
		b.persistNotices()
	}
}

// dropOldestNotice makes room for a new notice. Caller holds b.mu.
func (b *Broker) dropOldestNotice() {
	var oldest *storedNotice
	for _, n := range b.notices {
		if oldest == nil || n.Created.Before(oldest.Created) {
			oldest = n
		}
	}
	if oldest != nil {
		delete(b.notices, oldest.ID)
		b.publish(Event{Type: "notice-closed", ID: oldest.ID})
	}
}

// loadNotices restores the notices of a previous run.
func (b *Broker) loadNotices() error {
	if b.opts.NoticesFile == "" {
		return nil
	}
	data, err := os.ReadFile(b.opts.NoticesFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var list []*storedNotice
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("broker: reading %s: %w", b.opts.NoticesFile, err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.notices = map[string]*storedNotice{}
	for _, n := range list {
		if n.ID != "" && n.Expires.After(b.now()) {
			b.notices[n.ID] = n
		}
	}
	return nil
}

// persistNotices writes the notices. Caller holds b.mu.
func (b *Broker) persistNotices() {
	if b.opts.NoticesFile == "" {
		return
	}
	list := make([]*storedNotice, 0, len(b.notices))
	for _, n := range b.notices {
		list = append(list, n)
	}
	slices.SortFunc(list, func(x, y *storedNotice) int { return x.Created.Compare(y.Created) })
	data, err := json.MarshalIndent(list, "", "  ")
	if err == nil {
		err = writeFileAtomic(b.opts.NoticesFile, append(data, '\n'))
	}
	if err != nil {
		b.log.Warn("persisting notices failed", "err", err)
	}
}

// NoticesURL is the approval page's list (its inbox), where notices are
// shown: the gateway's page or a url_template ending in "/{id}"; else "".
func (b *Broker) NoticesURL() string {
	t := b.urlTemplate()
	if base, ok := strings.CutSuffix(t, "/{id}"); ok {
		return base + "/"
	}
	return ""
}
