package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/doctor"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

// callAs serves a request of a caller identified elsewhere (WithCaller),
// without peer credentials.
func callAs(t *testing.T, s *Server, a broker.Approver, via, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(WithCaller(context.Background(), a, via), method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// A caller the console signed in is taken as it is, needs no local
// password for its own request, and is audited as the console's, whatever
// its request names.
func TestWithCaller(t *testing.T) {
	s, id, outcome := setup(t)
	asked := 0
	s.OwnPassword = func(context.Context, transport.PeerCred, broker.Pending) error {
		asked++
		return context.Canceled
	}
	alice := broker.Approver{Name: "alice", UID: 1001, Remote: true, Issuer: "https://idp"}
	rec := callAs(t, s, alice, "console", "GET", "/v1/whoami", "")
	var who broker.Approver
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &who) != nil || who.Name != "alice" {
		t.Fatalf("whoami: %d %s", rec.Code, rec.Body)
	}
	if rec := callAs(t, s, broker.Approver{Name: "zed", Remote: true, NoUID: true}, "console", "GET", "/v1/approvals/"+id, ""); rec.Code != http.StatusNotFound {
		t.Errorf("another's approval: %d", rec.Code)
	}
	if rec := callAs(t, s, alice, "console", "POST", "/v1/approvals/"+id, `{"decision":"approve","scope":"once","via":"cli"}`); rec.Code != 200 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body)
	}
	if g := <-outcome; g == nil || asked != 0 {
		t.Fatalf("grant %v, asked for a password %d times", g, asked)
	}
	// Without a caller, peer credentials are needed.
	req := httptest.NewRequest("GET", "/v1/whoami", nil)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("without a caller: %d", rec.Code)
	}
}

func TestViaOf(t *testing.T) {
	plain := httptest.NewRequest("GET", "/", nil)
	if viaOf(plain, "cli") != "cli" || viaOf(plain, "x") != "api" || by(plain, broker.Approver{Name: "a"}) != "a (control API)" {
		t.Error("the socket's via")
	}
	r := plain.WithContext(WithCaller(context.Background(), broker.Approver{Name: "a"}, "console"))
	if viaOf(r, "cli") != "console" || by(r, broker.Approver{Name: "a"}) != "a (console)" {
		t.Error("the console's via")
	}
}

type fakeDoctor struct{ runs int }

func (f *fakeDoctor) Report(context.Context) DoctorReport {
	return DoctorReport{Trigger: "start", Results: []doctor.Result{{Check: "policy", ID: "policy", Status: doctor.OK, Summary: "OPA decides"}}}
}

func (f *fakeDoctor) Run(ctx context.Context) DoctorReport {
	f.runs++
	r := f.Report(ctx)
	r.Trigger = "request"
	return r
}

// /v1/doctor: for root and those review_policy allows; POST runs the
// checks; without the doctor in the gateway, 404.
func TestDoctorRoute(t *testing.T) {
	s, _, _ := setup(t)
	root := broker.Approver{Name: "root"}
	if rec := callAs(t, s, root, "", "GET", "/v1/doctor", ""); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "mcp-gateway-admin doctor") {
		t.Errorf("no doctor: %d %s", rec.Code, rec.Body)
	}
	d := &fakeDoctor{}
	s.Doctor = d
	rec := callAs(t, s, root, "", "GET", "/v1/doctor", "")
	var rep DoctorReport
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &rep) != nil || rep.Trigger != "start" || len(rep.Results) != 1 || d.runs != 0 {
		t.Errorf("GET: %d %s", rec.Code, rec.Body)
	}
	if rec := callAs(t, s, root, "", "POST", "/v1/doctor", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"trigger":"request"`) || d.runs != 1 {
		t.Errorf("POST: %d %s", rec.Code, rec.Body)
	}
	// alice, and an operator signed in (never root): no review_policy, no results.
	for _, a := range []broker.Approver{users[1001], {Name: "root", Remote: true}} {
		if rec := callAs(t, s, a, "console", "GET", "/v1/doctor", ""); rec.Code != http.StatusForbidden {
			t.Errorf("%+v: %d", a, rec.Code)
		}
	}
}
