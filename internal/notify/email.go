// Package notify sends e-mail about pending approvals, the mail part of
// the out-of-band push channel (docs/architecture.md, section 5.6.3).
// Recipients are policy: data.mcp.approvals.notify names the approvers of
// a request as local users and groups; groups are expanded through NSS,
// and each user becomes an address from the configured template.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/smtp"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
)

// notifyPath is the policy rule naming whom to tell.
const notifyPath = "/v1/data/mcp/approvals/notify"

// sendTimeout bounds one delivery to the mail server.
const sendTimeout = 30 * time.Second

// Policy answers the recipients query (pep.OPA implements it).
type Policy interface {
	Strings(ctx context.Context, path string, input any) ([]string, error)
}

// Email mails approvers about new pending approvals.
type Email struct {
	cfg      config.Email
	password string
	policy   Policy
	// URL returns the approval page for an approval id ("" if none).
	URL func(id string) string
	Log *slog.Logger
	// GroupMembers lists a group's members (default: getent group).
	GroupMembers func(ctx context.Context, group string) ([]string, error)
	// Send delivers a message (default: SMTP per cfg).
	Send func(ctx context.Context, to []string, msg []byte) error
	now  func() time.Time
	host string
}

// NewEmail returns the notifier for cfg.
func NewEmail(cfg config.Email, policy Policy, log *slog.Logger) (*Email, error) {
	e := &Email{cfg: cfg, policy: policy, Log: log, now: time.Now, GroupMembers: getentMembers}
	if cfg.PasswordFile != "" {
		b, err := os.ReadFile(cfg.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("notifications.email.password_file: %w", err)
		}
		e.password = strings.TrimRight(string(b), "\r\n")
	}
	e.host, _ = os.Hostname()
	e.Send = e.smtpSend
	if e.Log == nil {
		e.Log = slog.New(slog.DiscardHandler)
	}
	if e.URL == nil {
		e.URL = func(string) string { return "" }
	}
	return e, nil
}

// Run mails about the pending approvals announced on events until ctx
// ends or events is closed. Each approval is announced once.
func (e *Email) Run(ctx context.Context, events <-chan broker.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			if ev.Type == "pending" && ev.New && ev.Pending != nil {
				go e.notify(ctx, *ev.Pending)
			}
		}
	}
}

func (e *Email) notify(ctx context.Context, p broker.Pending) {
	to, err := e.Recipients(ctx, p)
	if err != nil {
		e.Log.Warn("approval mail: finding recipients failed", "id", p.ID, "err", err)
		return
	}
	if len(to) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	if err := e.Send(ctx, to, e.Message(p)); err != nil {
		e.Log.Warn("approval mail not sent", "id", p.ID, "err", err)
		return
	}
	e.Log.Info("approval mail sent", "id", p.ID, "recipients", len(to))
}

// Recipients returns the addresses to mail about p.
func (e *Email) Recipients(ctx context.Context, p broker.Pending) ([]string, error) {
	names, err := e.policy.Strings(ctx, notifyPath, broker.ApproverInput{Request: p.Target()})
	if err != nil {
		return nil, err
	}
	var users []string
	for _, n := range names {
		switch {
		case strings.HasPrefix(n, "user:"):
			users = append(users, strings.TrimPrefix(n, "user:"))
		case strings.HasPrefix(n, "group:"):
			members, err := e.GroupMembers(ctx, strings.TrimPrefix(n, "group:"))
			if err != nil {
				e.Log.Warn("approval mail: group lookup failed", "group", n, "err", err)
				continue
			}
			users = append(users, members...)
		}
	}
	var to []string
	for _, u := range users {
		if !validName(u) {
			continue
		}
		addr := strings.ReplaceAll(e.cfg.To, "{user}", u)
		if !slices.Contains(to, addr) {
			to = append(to, addr)
		}
	}
	return to, nil
}

// validName accepts plausible account names only (no header or SMTP
// command injection through odd names).
func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-$", c)
		if !ok {
			return false
		}
	}
	return true
}

// clean makes a value safe for a header line.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r < 0x20 {
			return ' '
		}
		return r
	}, s)
}

// Message formats the mail about p.
func (e *Email) Message(p broker.Pending) []byte {
	var b bytes.Buffer
	subject := fmt.Sprintf("[mcp-gateway] Approval needed: %s/%s for %s", p.Server, p.Name, p.Principal.Sub)
	hdr := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	hdr("From", clean(e.cfg.From))
	hdr("To", "undisclosed-recipients:;")
	hdr("Subject", mime.QEncoding.Encode("utf-8", clean(subject)))
	hdr("Date", e.now().Format(time.RFC1123Z))
	hdr("Message-ID", fmt.Sprintf("<%s@%s>", p.ID, clean(e.host)))
	hdr("Auto-Submitted", "auto-generated")
	hdr("MIME-Version", "1.0")
	hdr("Content-Type", "text/plain; charset=utf-8")
	hdr("Content-Transfer-Encoding", "8bit")
	b.WriteString("\r\n")

	// Values come from clients and backends: one line each.
	line := func(format string, a ...any) {
		for i, v := range a {
			if s, ok := v.(string); ok {
				a[i] = clean(s)
			}
		}
		fmt.Fprintf(&b, format+"\r\n", a...)
	}
	line("An AI agent asks for approval:")
	line("")
	who := p.Principal.Sub
	if p.Principal.Issuer != "" {
		who += " (" + p.Principal.Issuer + ")"
	}
	line("  Principal:  %s via %s", who, p.Principal.Transport)
	if p.Principal.Client.Name != "" {
		line("  Client:     %s %s (self-reported)", p.Principal.Client.Name, p.Principal.Client.Version)
	}
	line("  Call:       %s %s/%s", p.Action, p.Server, p.Name)
	if e.cfg.IncludeArgs && len(p.Args) > 0 {
		args, _ := json.MarshalIndent(p.Args, "              ", "  ")
		fmt.Fprintf(&b, "  Arguments:  %s\r\n", strings.ReplaceAll(string(args), "\n", "\r\n"))
	}
	line("  Times out:  %s", p.Expires.Local().Format(time.RFC1123))
	line("")
	if u := e.URL(p.ID); u != "" {
		line("Decide on the approval page: %s", u)
	} else {
		line("Decide in the MCP Gateway page of Cockpit (Approvals), approval %s.", p.ID)
	}
	line("")
	line("Only approve what you expect. This mail is informational: approving")
	line("happens on the page, where you authenticate.")
	return b.Bytes()
}

// smtpSend delivers msg through the configured mail server.
func (e *Email) smtpSend(ctx context.Context, to []string, msg []byte) error {
	host, _, _ := net.SplitHostPort(e.cfg.SMTP)
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", e.cfg.SMTP)
	if err != nil {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = c.Close() }()
	if err := c.Hello(e.host); err != nil {
		return err
	}
	if ok, _ := c.Extension("STARTTLS"); ok && e.cfg.StartTLS != "never" {
		if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	} else if e.cfg.StartTLS == "always" {
		return errors.New("notify: the mail server does not offer STARTTLS")
	}
	if e.cfg.Username != "" {
		// PlainAuth refuses to send the password unencrypted except to
		// localhost.
		if err := c.Auth(smtp.PlainAuth("", e.cfg.Username, e.password, host)); err != nil {
			return err
		}
	}
	if err := c.Mail(e.cfg.From); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("recipient %s: %w", rcpt, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// getentMembers lists a group's members through NSS (also SSSD, LDAP):
// those its entry lists, and the users whose primary group it is, as far
// as NSS enumerates users (SSSD and LDAP often do not, without
// enumerate = true).
func getentMembers(ctx context.Context, group string) ([]string, error) {
	if !validName(group) {
		return nil, fmt.Errorf("invalid group name %q", group)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "getent", "group", group).Output()
	if err != nil {
		return nil, err
	}
	gid, members := parseGroup(string(out))
	if gid == "" {
		return members, nil
	}
	// An enumeration that fails leaves the listed members.
	if passwd, err := exec.CommandContext(ctx, "getent", "passwd").Output(); err == nil {
		members = appendNew(members, primaryMembers(string(passwd), gid)...)
	}
	return members, nil
}

// parseGroup returns the gid and the listed members of a group entry
// (name:password:gid:members).
func parseGroup(entry string) (gid string, members []string) {
	fields := strings.Split(strings.TrimSpace(entry), ":")
	if len(fields) < 4 {
		return "", nil
	}
	if fields[3] != "" {
		members = strings.Split(fields[3], ",")
	}
	return fields[2], members
}

// primaryMembers returns the users of passwd entries (name:password:uid:
// gid:...) whose primary group is gid.
func primaryMembers(passwd, gid string) []string {
	var users []string
	for _, line := range strings.Split(passwd, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 4 && fields[3] == gid && fields[0] != "" {
			users = append(users, fields[0])
		}
	}
	return users
}

// appendNew appends the names not in list yet.
func appendNew(list []string, names ...string) []string {
	for _, n := range names {
		if !slices.Contains(list, n) {
			list = append(list, n)
		}
	}
	return list
}
