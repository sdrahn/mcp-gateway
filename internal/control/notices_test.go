package control

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

// noticeServer is a control server without approver policy (a notice is
// for its principal themself), root identified too, and alice a local
// account with uid 1001.
func noticeServer(t *testing.T) *Server {
	t.Helper()
	b, err := broker.New(broker.Options{Timeout: 5 * time.Second, OOB: true})
	if err != nil {
		t.Fatal(err)
	}
	return &Server{Broker: b,
		Identify: func(p transport.PeerCred) (broker.Approver, error) {
			if p.UID == 0 {
				return broker.Approver{Name: "root", UID: 0}, nil
			}
			return identify(p)
		},
		LookupPrincipal: func(name string) principal.Principal {
			if name == "alice" {
				uid := uint32(1001)
				return principal.Principal{Sub: name, UID: &uid}
			}
			return principal.Principal{Sub: name}
		}}
}

// as calls s as the local account uid (0: root).
func as(t *testing.T, s *Server, uid uint32, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req = req.WithContext(WithPeer(req.Context(), transport.PeerCred{UID: uid}))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

const demotion = `{"principal": "alice", "servers": ["zypp"], "severity": "warning",
	"title": "patch-errata demoted", "text": "Override rate 7.1 % above 5.0 %: back to supervised."}`

func TestNotices(t *testing.T) {
	s := noticeServer(t)
	if rec := as(t, s, 1001, "POST", "/v1/notices", demotion); rec.Code != http.StatusForbidden {
		t.Fatalf("posted by a user: %d %s", rec.Code, rec.Body)
	}
	for name, body := range map[string]string{
		"not JSON":      `{`,
		"unknown field": `{"principal": "alice", "title": "x", "decision": "approve"}`,
		"no title":      `{"principal": "alice"}`,
	} {
		if rec := as(t, s, 0, "POST", "/v1/notices", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	rec := as(t, s, 0, "POST", "/v1/notices", demotion)
	var n broker.Notice
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &n) != nil || n.ID == "" ||
		n.PostedBy != "root" || n.Principal.UID == nil || *n.Principal.UID != 1001 {
		t.Fatalf("post: %d %s", rec.Code, rec.Body)
	}

	var list []broker.Notice
	if rec := as(t, s, 1001, "GET", "/v1/notices", ""); rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &list) != nil ||
		len(list) != 1 || list[0].ID != n.ID || list[0].Title != "patch-errata demoted" {
		t.Fatalf("alice's notices: %s", rec.Body)
	}
	if rec := as(t, s, 1002, "GET", "/v1/notices", ""); strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("bob's notices: %s", rec.Body)
	}
	if rec := as(t, s, 1002, "POST", "/v1/notices/"+n.ID+"/dismiss", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("bob dismissed alice's notice: %d", rec.Code)
	}
	if rec := as(t, s, 1001, "POST", "/v1/notices/"+n.ID+"/dismiss", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("dismiss: %d %s", rec.Code, rec.Body)
	}
	if rec := as(t, s, 1001, "GET", "/v1/notices", ""); strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("after dismissing: %s", rec.Body)
	}
}

// The event stream carries the notices its caller may read: those
// posted before it opened, then new ones, and their end when the caller
// dismisses one; not others' dismissals.
func TestNoticeEvents(t *testing.T) {
	s := noticeServer(t)
	if rec := as(t, s, 0, "POST", "/v1/notices", demotion); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body)
	}
	srv := httptest.NewUnstartedServer(s.Handler())
	srv.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return WithPeer(ctx, transport.PeerCred{UID: 1001})
	}
	srv.Start()
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + "/v1/events")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	events := make(chan approvalEvent, 8)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if data, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				var ev approvalEvent
				if json.Unmarshal([]byte(data), &ev) == nil {
					events <- ev
				}
			}
		}
		close(events)
	}()
	next := func() approvalEvent {
		t.Helper()
		select {
		case ev := <-events:
			return ev
		case <-time.After(3 * time.Second):
			t.Fatal("no event")
		}
		return approvalEvent{}
	}
	first := next()
	if first.Type != "notice" || first.Notice == nil || first.Notice.Title != "patch-errata demoted" {
		t.Fatalf("first %+v", first)
	}
	// A notice for bob is not alice's to see.
	if rec := as(t, s, 0, "POST", "/v1/notices", `{"principal": "bob", "title": "for bob"}`); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body)
	}
	rec := as(t, s, 0, "POST", "/v1/notices", `{"principal": "alice", "title": "second"}`)
	var second broker.Notice
	_ = json.Unmarshal(rec.Body.Bytes(), &second)
	if ev := next(); ev.Type != "notice" || !ev.New || ev.ID != second.ID {
		t.Fatalf("new notice %+v", ev)
	}
	if rec := as(t, s, 1001, "POST", "/v1/notices/"+first.ID+"/dismiss", ""); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Code)
	}
	if ev := next(); ev.Type != "notice-closed" || ev.ID != first.ID {
		t.Fatalf("dismissed %+v", ev)
	}
	select {
	case ev := <-events:
		t.Fatalf("unexpected %+v", ev)
	case <-time.After(100 * time.Millisecond):
	}
}
