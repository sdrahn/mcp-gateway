package broker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/audit"
)

// noticePolicy: custos may post; the patchers group approves zypp, olga
// owns agent-patch-pilot (as an added allow rule would say); mail for
// zypp goes to the patchers.
type noticePolicy struct{}

func (noticePolicy) Bool(_ context.Context, path string, input any) (bool, error) {
	in := input.(ApproverInput)
	switch path {
	case postNoticePath:
		return in.Approver.Name == "custos" && in.Notice != nil, nil
	case approvePath:
		if in.Request.Action != "notice" || in.Notice == nil || in.Notice.Principal != in.Request.Principal.Sub {
			return false, nil
		}
		return in.Request.Server == "zypp" && slices.Contains(in.Approver.Groups, "patchers") ||
			in.Request.Principal.Sub == "agent-patch-pilot" && in.Approver.Name == "olga", nil
	}
	return false, nil
}

func (noticePolicy) Strings(_ context.Context, path string, input any) ([]string, error) {
	in := input.(ApproverInput)
	if path == NotifyPath && in.Request.Server == "zypp" {
		return []string{"group:patchers"}, nil
	}
	return nil, nil
}

var (
	rootApprover = Approver{Name: "root", UID: 0}
	custos       = Approver{Name: "custos", UID: 990}
	pat          = Approver{Name: "pat", UID: 1200, Groups: []string{"patchers"}}
	olga         = Approver{Name: "olga", UID: 1300}
	bobby        = Approver{Name: "bobby", UID: 1400}
)

func demotion() Notice {
	return Notice{Principal: NoticePrincipal{Sub: "agent-patch-pilot"}, Servers: []string{"zypp"},
		Severity: SeverityWarning, Title: "patch-errata demoted", Text: "Override rate 7.1 % above 5.0 %:\nback to supervised."}
}

func TestPostNotice(t *testing.T) {
	k := &kernelLog{}
	b := newBroker(t, func(o *Options) {
		o.Policy = noticePolicy{}
		o.Audit = audit.New(&strings.Builder{}, audit.Options{Kernel: k})
	})
	events, stop := b.Subscribe()
	defer stop()

	if _, err := b.PostNotice(t.Context(), pat, demotion()); !errors.Is(err, ErrForbidden) {
		t.Fatalf("an approver posted: %v", err)
	}
	remote := Approver{Name: "custos", Remote: true, NoUID: true}
	if _, err := b.PostNotice(t.Context(), remote, demotion()); !errors.Is(err, ErrForbidden) {
		t.Fatalf("a remote approver posted: %v", err)
	}
	n, err := b.PostNotice(t.Context(), rootApprover, demotion())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(n.ID, "n-") || n.PostedBy != "root" || !n.Expires.Equal(n.Created.Add(NoticeTTL)) {
		t.Fatalf("notice %+v", n)
	}
	if _, err := b.PostNotice(t.Context(), custos, demotion()); err != nil {
		t.Fatalf("post_notice allows custos: %v", err)
	}
	select {
	case ev := <-events:
		if ev.Type != "notice" || ev.ID != n.ID || !ev.New || ev.Notice == nil || ev.Notice.Title != "patch-errata demoted" {
			t.Fatalf("event %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no event")
	}
	if len(k.msgs) != 2 || !strings.Contains(k.msgs[0], "op=mcp-notice") || !strings.Contains(k.msgs[0], "by=root") ||
		!strings.Contains(k.msgs[0], "principal=agent-patch-pilot") || !strings.Contains(k.msgs[0], "notify=group:patchers") ||
		!strings.Contains(k.msgs[0], "servers=zypp") {
		t.Fatalf("audit %v", k.msgs)
	}

	// The audience: the server's approvers and the owner, not others.
	for _, tc := range []struct {
		a    Approver
		want int
	}{{pat, 2}, {olga, 2}, {rootApprover, 2}, {bobby, 0}, {custos, 0}} {
		if got := b.ListNotices(t.Context(), tc.a); len(got) != tc.want {
			t.Errorf("%s sees %d notices, want %d", tc.a.Name, len(got), tc.want)
		}
	}

	// Dismissed for the reader only.
	if err := b.DismissNotice(t.Context(), bobby, n.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("dismissed by one who may not read it: %v", err)
	}
	if err := b.DismissNotice(t.Context(), pat, n.ID); err != nil {
		t.Fatal(err)
	}
	if got := b.ListNotices(t.Context(), pat); len(got) != 1 || got[0].ID == n.ID {
		t.Fatalf("after dismissing: %+v", got)
	}
	if got := b.ListNotices(t.Context(), olga); len(got) != 2 {
		t.Fatalf("olga's notices went with pat's dismissal: %+v", got)
	}
}

func TestNoticeValidation(t *testing.T) {
	b := newBroker(t, nil)
	for name, mod := range map[string]func(*Notice){
		"no title":       func(n *Notice) { n.Title = " " },
		"long title":     func(n *Notice) { n.Title = strings.Repeat("t", MaxNoticeTitle+1) },
		"two-line title": func(n *Notice) { n.Title = "a\nb" },
		"long text":      func(n *Notice) { n.Text = strings.Repeat("t", MaxNoticeText+1) },
		"escape in text": func(n *Notice) { n.Text = "a\x1b[2Jb" },
		"invalid UTF-8":  func(n *Notice) { n.Text = "a\xffb" },
		"no principal":   func(n *Notice) { n.Principal.Sub = "" },
		"severity":       func(n *Notice) { n.Severity = "critical" },
		"empty server":   func(n *Notice) { n.Servers = []string{""} },
		"too many servers": func(n *Notice) {
			n.Servers = make([]string, maxNoticeServers+1)
			for i := range n.Servers {
				n.Servers[i] = "s"
			}
		},
	} {
		n := demotion()
		mod(&n)
		if _, err := b.PostNotice(t.Context(), rootApprover, n); !errors.Is(err, ErrBadNotice) {
			t.Errorf("%s: %v", name, err)
		}
	}
	n := demotion()
	n.Severity = ""
	n.Servers = []string{"zypp", "fs", "zypp"}
	got, err := b.PostNotice(t.Context(), rootApprover, n)
	if err != nil || got.Severity != SeverityInfo || strings.Join(got.Servers, ",") != "fs,zypp" {
		t.Fatalf("defaults: %+v %v", got, err)
	}
}

// Without approver policy, a notice is for the principal themself.
func TestNoticeWithoutPolicy(t *testing.T) {
	b := newBroker(t, func(o *Options) { o.Policy = nil })
	uid := uint32(1500)
	n := demotion()
	n.Principal.UID = &uid
	if _, err := b.PostNotice(t.Context(), rootApprover, n); err != nil {
		t.Fatal(err)
	}
	if got := b.ListNotices(t.Context(), Approver{Name: "agent", UID: 1500}); len(got) != 1 {
		t.Fatalf("the principal: %+v", got)
	}
	if got := b.ListNotices(t.Context(), pat); len(got) != 0 {
		t.Fatalf("another user: %+v", got)
	}
	if _, err := b.PostNotice(t.Context(), pat, n); !errors.Is(err, ErrForbidden) {
		t.Fatalf("posted by a user: %v", err)
	}
}

// Notices survive a restart with their dismissals, until they expire; the
// oldest go when there are too many.
func TestNoticesKeptAndExpired(t *testing.T) {
	file := filepath.Join(t.TempDir(), "notices.json")
	now := time.Now()
	mod := func(o *Options) { o.Policy = noticePolicy{}; o.NoticesFile = file }
	b := newBroker(t, mod)
	b.now = func() time.Time { return now }
	n, err := b.PostNotice(t.Context(), rootApprover, demotion())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.DismissNotice(t.Context(), pat, n.ID); err != nil {
		t.Fatal(err)
	}
	b = newBroker(t, mod)
	b.now = func() time.Time { return now }
	if got := b.ListNotices(t.Context(), olga); len(got) != 1 || got[0].ID != n.ID || got[0].Text != demotion().Text {
		t.Fatalf("restored: %+v", got)
	}
	if !b.NoticeDismissed(pat, n.ID) || len(b.ListNotices(t.Context(), pat)) != 0 {
		t.Fatal("the dismissal was not kept")
	}

	events, stop := b.Subscribe()
	defer stop()
	now = now.Add(NoticeTTL)
	if got := b.ListNotices(t.Context(), olga); len(got) != 0 {
		t.Fatalf("expired notice listed: %+v", got)
	}
	if ev := <-events; ev.Type != "notice-closed" || ev.ID != n.ID || ev.Reader != "" {
		t.Fatalf("expiry event %+v", ev)
	}
	if data, _ := os.ReadFile(file); strings.Contains(string(data), n.ID) {
		t.Fatalf("expired notice kept: %s", data)
	}

	for i := 0; i < MaxNotices+1; i++ {
		now = now.Add(time.Second)
		if _, err := b.PostNotice(t.Context(), rootApprover, demotion()); err != nil {
			t.Fatal(err)
		}
	}
	if got := b.ListNotices(t.Context(), olga); len(got) != MaxNotices {
		t.Fatalf("%d notices kept, want %d", len(got), MaxNotices)
	}
}
