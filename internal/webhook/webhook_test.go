package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

var secret = []byte("0123456789abcdef0123456789abcdef")

func TestSignVerify(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	body := []byte(`{"id":"a-1"}`)
	h := Sign(secret, body, now)
	if !strings.HasPrefix(h, "t=1800000000,v1=") {
		t.Fatalf("header %q", h)
	}
	if _, err := Verify(secret, body, h, now.Add(time.Minute)); err != nil {
		t.Errorf("valid: %v", err)
	}
	// What one side signs is not the other's: a post's signature is no
	// callback's, and the other way round.
	cb := SignCallback(secret, body, now)
	if _, err := VerifyCallback(secret, body, cb, now); err != nil {
		t.Errorf("valid callback: %v", err)
	}
	if _, err := VerifyCallback(secret, body, h, now); err == nil {
		t.Error("a post's signature verifies as a callback's")
	}
	if _, err := Verify(secret, body, cb, now); err == nil {
		t.Error("a callback's signature verifies as a post's")
	}
	for name, c := range map[string]struct {
		secret, body []byte
		header       string
		at           time.Time
		want         string
	}{
		"unsigned":        {secret, body, "", now, "not signed"},
		"no signature":    {secret, body, "t=1800000000", now, "not signed"},
		"bad timestamp":   {secret, body, "t=x,v1=00", now, "bad timestamp"},
		"stale":           {secret, body, h, now.Add(6 * time.Minute), "more than 5m0s"},
		"from the future": {secret, body, h, now.Add(-6 * time.Minute), "more than 5m0s"},
		"another body":    {secret, []byte(`{"id":"a-2"}`), h, now, "does not match"},
		"another secret":  {[]byte("another secret, as long as it is"), body, h, now, "does not match"},
		"timestamp moved": {secret, body, strings.Replace(h, "t=1800000000", "t=1800000001", 1), now, "does not match"},
	} {
		if _, err := Verify(c.secret, c.body, c.header, c.at); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

type fakeBroker struct {
	mu       sync.Mutex
	ch       chan broker.Event
	resolved []string
	err      error
	servers  map[string]string // pending approval id → server; nil: any id is fs's
}

func (b *fakeBroker) GetPending(_ context.Context, _ broker.Approver, id string) (broker.Pending, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.servers == nil {
		return broker.Pending{ID: id, Server: "fs"}, nil
	}
	srv, ok := b.servers[id]
	if !ok {
		return broker.Pending{}, broker.ErrNotFound
	}
	return broker.Pending{ID: id, Server: srv}, nil
}

func (b *fakeBroker) Subscribe() (<-chan broker.Event, func()) { return b.ch, func() {} }
func (b *fakeBroker) ApprovalURL(id string) string             { return "https://gw/approvals/" + id }
func (b *fakeBroker) ResolveVia(_ context.Context, a broker.Approver, id string, approve bool, scope, via string) (*pep.Grant, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.err != nil {
		return nil, b.err
	}
	d := "deny"
	if approve {
		d = "approve"
	}
	b.resolved = append(b.resolved, strings.Join([]string{id, d, scope, via, a.Name, a.Issuer,
		map[bool]string{true: "remote", false: "local"}[a.Remote], map[bool]string{true: "nouid", false: "uid"}[a.NoUID]}, " "))
	return nil, nil
}

type fakeAudit struct {
	mu     sync.Mutex
	events []string
}

func (a *fakeAudit) Event(op string, ok bool, f map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, op+" "+map[bool]string{true: "ok", false: "refused"}[ok]+" "+f["webhook"]+" "+f["approver"]+" "+f["id"]+" "+f["reason"])
}

type received struct {
	kind, sig string
	body      []byte
}

// receiver is a webhook receiver recording what it got; it fails the
// first fail posts.
func receiver(t *testing.T, fail int) (*httptest.Server, chan received) {
	t.Helper()
	got := make(chan received, 10)
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if fail > 0 {
			fail--
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		b, _ := io.ReadAll(r.Body)
		got <- received{r.Header.Get(EventHeader), r.Header.Get(SignatureHeader), b}
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func pending(id, server string) broker.Event {
	p := broker.Pending{ID: id, Server: server, Name: "write_file", Action: "tools/call",
		Principal: principal.Principal{Sub: "ivy", Client: principal.Client{Name: "kit", Version: "1.2"}},
		Args:      map[string]any{"path": "/etc/secret"}, Scopes: []string{"once", "1h"}, Waiting: true}
	return broker.Event{Type: "pending", ID: id, New: true, Pending: &p}
}

func next(t *testing.T, ch chan received) received {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(10 * time.Second):
		t.Fatal("nothing posted")
		return received{}
	}
}

func TestPosts(t *testing.T) {
	firstRetry = 10 * time.Millisecond
	chat, chatGot := receiver(t, 1) // the first post fails: tried again
	tickets, ticketsGot := receiver(t, 0)
	b := &fakeBroker{ch: make(chan broker.Event, 10)}
	h := &Hooks{
		Hooks: []Hook{
			{Name: "chat", URL: chat.URL, Secret: secret},
			{Name: "tickets", URL: tickets.URL, Secret: []byte("tickets' secret, 32 characters.."), IncludeArgs: true, Servers: []string{"zypp"}},
		},
		Broker: b, Callback: "https://gw/approvals/webhook/{name}", Gateway: "gw", Client: chat.Client(),
	}
	// Both test servers share the certificate of httptest.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.Run(ctx)

	b.ch <- pending("a-1", "fs")
	r := next(t, chatGot)
	if r.kind != "pending" {
		t.Errorf("event %q", r.kind)
	}
	if _, err := Verify(secret, r.body, r.sig, time.Now()); err != nil {
		t.Errorf("signature: %v", err)
	}
	var ev Event
	if err := json.Unmarshal(r.body, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.ID != "a-1" || ev.Gateway != "gw" || ev.Call.Server != "fs" || ev.Call.Principal != "ivy" || ev.Call.Client != "kit 1.2" ||
		ev.URL != "https://gw/approvals/a-1" || ev.Callback != "https://gw/approvals/webhook/chat" || !ev.Call.Waiting {
		t.Errorf("post %s", r.body)
	}
	if strings.Contains(string(r.body), "/etc/secret") || ev.Call.Args != nil {
		t.Errorf("arguments posted without include_args: %s", r.body)
	}

	// tickets: only zypp's approvals, with the arguments.
	b.ch <- pending("a-2", "zypp")
	r = next(t, ticketsGot)
	_ = json.Unmarshal(r.body, &ev)
	if ev.ID != "a-2" || ev.Call.Args["path"] != "/etc/secret" || ev.Callback != "https://gw/approvals/webhook/tickets" {
		t.Errorf("tickets' post %s", r.body)
	}
	if _, err := Verify(secret, r.body, r.sig, time.Now()); err == nil {
		t.Error("signed with chat's secret")
	}
	if r = next(t, chatGot); !strings.Contains(string(r.body), `"id":"a-2"`) {
		t.Errorf("chat %s", r.body)
	}
	// Announced again (a new attempt): not posted again.
	again := pending("a-2", "zypp")
	again.New = false
	b.ch <- again
	// Resolved: to the hooks that got the approval.
	b.ch <- broker.Event{Type: "resolved", ID: "a-1"}
	if r = next(t, chatGot); r.kind != "resolved" || !strings.Contains(string(r.body), `"id":"a-1"`) {
		t.Errorf("resolved %s %s", r.kind, r.body)
	}
	select {
	case r := <-ticketsGot:
		t.Errorf("tickets got %s", r.body)
	case r := <-chatGot:
		t.Errorf("chat got %s", r.body)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestSendFails(t *testing.T) {
	firstRetry = 10 * time.Millisecond
	srv, _ := receiver(t, 5)
	h := &Hooks{Client: srv.Client()}
	err := h.Send(context.Background(), &Hook{Name: "chat", URL: srv.URL, Secret: secret}, Event{Type: "ping"})
	if err == nil || !strings.Contains(err.Error(), "502 Bad Gateway") {
		t.Errorf("err %v", err)
	}
}

type fixture struct {
	h     *Hooks
	b     *fakeBroker
	audit *fakeAudit
	srv   *httptest.Server
	now   time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{b: &fakeBroker{}, audit: &fakeAudit{}, now: time.Now()}
	f.h = &Hooks{Hooks: []Hook{{Name: "chat", Secret: secret, LocalAccounts: true}, {Name: "tickets-x", Secret: secret}}, Broker: f.b, Audit: f.audit,
		now: func() time.Time { return f.now },
		lookupUser: func(name string) (broker.Approver, error) {
			switch name {
			case "erin":
				return broker.Approver{Name: "erin", UID: 1001, Groups: []string{"ops"}}, nil
			case "root":
				return broker.Approver{Name: "root", UID: 0}, nil
			}
			return broker.Approver{}, errors.New("unknown user")
		}}
	f.srv = httptest.NewServer(f.h.Handler())
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) call(t *testing.T, hook, sig, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", f.srv.URL+"/approvals/webhook/"+hook, strings.NewReader(body))
	if sig != "" {
		req.Header.Set(SignatureHeader, sig)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (f *fixture) signed(t *testing.T, body string) (int, string) {
	t.Helper()
	return f.call(t, "chat", SignCallback(secret, []byte(body), f.now), body)
}

func TestCallback(t *testing.T) {
	f := newFixture(t)
	body := `{"id":"a-1","decision":"approve","scope":"1h","approver":"remote-user:jack@example.com","groups":["ops"]}`
	if code, b := f.signed(t, body); code != 204 {
		t.Fatalf("callback: %d %s", code, b)
	}
	if len(f.b.resolved) != 1 || f.b.resolved[0] != "a-1 approve 1h webhook jack@example.com webhook:chat remote nouid" {
		t.Errorf("resolved %v", f.b.resolved)
	}
	// The same callback again: refused, even though its signature holds.
	if code, b := f.signed(t, body); code != 409 || !strings.Contains(b, "replayed") {
		t.Errorf("replay: %d %s", code, b)
	}
	// A local account: looked up, but remote (never root).
	if code, b := f.signed(t, `{"id":"a-2","decision":"deny","approver":"user:erin"}`); code != 204 {
		t.Errorf("erin: %d %s", code, b)
	}
	if len(f.b.resolved) != 2 || f.b.resolved[1] != "a-2 deny  webhook erin webhook:chat remote uid" {
		t.Errorf("resolved %v", f.b.resolved)
	}
	f.audit.mu.Lock()
	if len(f.audit.events) != 3 || f.audit.events[0] != "mcp-webhook-callback ok chat remote-user:jack@example.com a-1 " ||
		!strings.HasPrefix(f.audit.events[1], "mcp-webhook-callback refused chat") {
		t.Errorf("audit %q", f.audit.events)
	}
	f.audit.mu.Unlock()
}

func TestCallbackRefused(t *testing.T) {
	f := newFixture(t)
	ok := `{"id":"a-1","decision":"approve","approver":"remote-user:jack"}`
	for name, c := range map[string]struct {
		hook, sig, body string
		status          int
		want            string
	}{
		"unsigned":                     {"chat", "", ok, 401, "not signed"},
		"wrong secret":                 {"chat", SignCallback([]byte("not the secret, but just as long"), []byte(ok), time.Now()), ok, 401, "does not match"},
		"signed as a post":             {"chat", Sign(secret, []byte(ok), time.Now()), ok, 401, "does not match"},
		"stale":                        {"chat", SignCallback(secret, []byte(ok), time.Now().Add(-10*time.Minute)), ok, 401, "more than 5m0s"},
		"no such webhook":              {"tickets", SignCallback(secret, []byte(ok), time.Now()), ok, 404, "no such webhook"},
		"bad decision":                 {"chat", "", `{"id":"a-1","decision":"maybe","approver":"remote-user:jack"}`, 400, "decision must be"},
		"no approver":                  {"chat", "", `{"id":"a-1","decision":"approve"}`, 400, "approver must be"},
		"a role":                       {"chat", "", `{"id":"a-1","decision":"approve","approver":"role:admin"}`, 400, "approver must be"},
		"no such account":              {"chat", "", `{"id":"a-1","decision":"approve","approver":"user:nobody-here"}`, 400, "no such local account"},
		"a local account, not allowed": {"tickets-x", "", `{"id":"a-1","decision":"approve","approver":"user:erin"}`, 400, "may not name local accounts"},
		"not JSON":                     {"chat", "", `approve a-1`, 400, "invalid body"},
	} {
		sig := c.sig
		if sig == "" && name != "unsigned" {
			f.now = f.now.Add(time.Second) // a new signature each
			sig = SignCallback(secret, []byte(c.body), f.now)
		}
		if code, b := f.call(t, c.hook, sig, c.body); code != c.status || !strings.Contains(b, c.want) {
			t.Errorf("%s: %d %s, want %d %q", name, code, b, c.status, c.want)
		}
	}
	if len(f.b.resolved) != 0 {
		t.Errorf("decided %v", f.b.resolved)
	}
	// Only what the receiver signed is audited.
	f.audit.mu.Lock()
	for _, ev := range f.audit.events {
		if strings.Contains(ev, "not signed") || strings.Contains(ev, "does not match") || strings.Contains(ev, "more than 5m0s") {
			t.Errorf("audited: %q", ev)
		}
	}
	f.audit.mu.Unlock()
	// The approver rules: the broker refuses whom they do not allow.
	for err, want := range map[error]int{broker.ErrForbidden: 404, broker.ErrNotFound: 404, broker.ErrBadScope: 400} {
		f.b.err = err
		body := `{"id":"a-1","decision":"approve","approver":"remote-user:kim","scope":"` + err.Error() + `"}`
		if code, b := f.signed(t, body); code != want {
			t.Errorf("%v: %d %s", err, code, b)
		}
	}
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	if last := f.audit.events[len(f.audit.events)-1]; !strings.HasPrefix(last, "mcp-webhook-callback refused chat remote-user:kim a-1 ") {
		t.Errorf("audit %q", last)
	}
}

func TestReplaysForgotten(t *testing.T) {
	f := newFixture(t)
	if !f.h.firstUse("k", f.now.Add(time.Minute)) || f.h.firstUse("k", f.now.Add(time.Minute)) {
		t.Fatal("first use")
	}
	f.now = f.now.Add(2 * time.Minute)
	if !f.h.firstUse("k", f.now.Add(time.Minute)) {
		t.Error("a lapsed key is still refused")
	}
}

// A webhook with servers decides only those servers' approvals.
func TestCallbackServers(t *testing.T) {
	f := newFixture(t)
	f.h.Hooks = append(f.h.Hooks, Hook{Name: "zypp-only", Secret: secret, Servers: []string{"zypp"}})
	f.b.servers = map[string]string{"a-fs": "fs", "a-zypp": "zypp"}
	call := func(id string) (int, string) {
		f.now = f.now.Add(time.Second)
		body := `{"id":"` + id + `","decision":"approve","scope":"once","approver":"remote-user:jack"}`
		return f.call(t, "zypp-only", SignCallback(secret, []byte(body), f.now), body)
	}
	if code, b := call("a-fs"); code != 404 || !strings.Contains(b, "no such approval of this webhook's servers") {
		t.Errorf("fs's approval: %d %s", code, b)
	}
	if code, b := call("a-gone"); code != 404 {
		t.Errorf("unknown approval: %d %s", code, b)
	}
	if len(f.b.resolved) != 0 {
		t.Fatalf("decided %v", f.b.resolved)
	}
	if code, b := call("a-zypp"); code != 204 || len(f.b.resolved) != 1 {
		t.Errorf("zypp's approval: %d %s %v", code, b, f.b.resolved)
	}
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	if !strings.HasPrefix(f.audit.events[0], "mcp-webhook-callback refused zypp-only remote-user:jack a-fs ") {
		t.Errorf("audit %q", f.audit.events)
	}
}

// Posts follow no redirect: it would take the signed body (and with
// include_args the arguments) elsewhere.
func TestNoRedirects(t *testing.T) {
	firstRetry = 10 * time.Millisecond
	elsewhere, got := receiver(t, 0)
	redirecting := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/stolen", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirecting.Close)
	h := &Hooks{Client: redirecting.Client()}
	err := h.Send(context.Background(), &Hook{Name: "chat", URL: redirecting.URL, Secret: secret}, Event{Type: "pending", ID: "a-1"})
	if err == nil || !strings.Contains(err.Error(), "307 Temporary Redirect to "+elsewhere.URL+"/stolen: redirects are not followed") {
		t.Errorf("err %v", err)
	}
	select {
	case r := <-got:
		t.Errorf("the redirect was followed: %s", r.body)
	case <-time.After(100 * time.Millisecond):
	}
	if h.Client == redirecting.Client() || redirecting.Client().CheckRedirect != nil {
		t.Error("the client given was changed, not copied")
	}
}
