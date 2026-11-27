package approvalpage

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/control"
)

// consoleFixture is a page whose console API serves a control API
// without a broker: whoami and the 404s of an empty gateway are enough
// to see who the caller is and what is let through.
func consoleFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t, func(pg *Page) {
		pg.Control = (&control.Server{}).Handler()
		pg.DeviceClientID = "approvals-cli"
	})
	return f
}

func do(t *testing.T, c *http.Client, method, u string, hdr map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestConsoleAPI(t *testing.T) {
	f := consoleFixture(t)
	api := f.srv.URL + "/console/api/v1/"

	// Not signed in: 401, no redirect.
	if code, body := do(t, f.noRedirects(), "GET", api+"whoami", nil); code != 401 || !strings.Contains(body, "/approvals/") {
		t.Errorf("not signed in: %d %s", code, body)
	}

	// Signed in on the page: the cookie counts.
	c := f.browser(t)
	if code, _, _ := get(t, c, f.srv.URL+"/approvals/"); code != 200 {
		t.Fatal(code)
	}
	code, body := do(t, c, "GET", api+"session", nil)
	var sess consoleSession
	if code != 200 || json.Unmarshal([]byte(body), &sess) != nil || sess.Name != "jack" || sess.CSRF == "" || sess.Expires.IsZero() {
		t.Fatalf("session: %d %s", code, body)
	}
	if code, body := do(t, c, "GET", api+"whoami", nil); code != 200 || !strings.Contains(body, `"name":"jack"`) || !strings.Contains(body, `"ops"`) {
		t.Errorf("whoami: %d %s", code, body)
	}
	if code, body := do(t, c, "GET", api+"nonsense", nil); code != 404 {
		t.Errorf("an unknown route: %d %s", code, body)
	}

	// Changes need the CSRF token, from the page's origin.
	events := len(f.audit.events)
	for name, hdr := range map[string]map[string]string{
		"without the CSRF token": nil,
		"with a wrong token":     {csrfHeader: "x" + sess.CSRF},
		"from another origin":    {csrfHeader: sess.CSRF, "Origin": "https://evil.example"},
		"from another site":      {csrfHeader: sess.CSRF, "Sec-Fetch-Site": "cross-site"},
	} {
		if code, body := do(t, c, "DELETE", api+"instances/i-1", hdr); code != 403 {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	if len(f.audit.events) != events {
		t.Errorf("refusals audited as actions: %v", f.audit.events[events:])
	}
	code, body = do(t, c, "DELETE", api+"instances/i-1", map[string]string{csrfHeader: sess.CSRF, "Origin": f.srv.URL, "Sec-Fetch-Site": "same-origin"})
	if code != 404 || !strings.Contains(body, "no such instance") {
		t.Errorf("with the token: %d %s", code, body)
	}
	if n := len(f.audit.fields); n != events+1 || f.audit.fields[n-1]["by"] != "jack" || f.audit.fields[n-1]["via"] != ViaConsole ||
		f.audit.fields[n-1]["route"] != "/v1/instances/i-1" || f.audit.fields[n-1]["method"] != "DELETE" ||
		!strings.HasPrefix(f.audit.events[n-1], "mcp-console-action failed") {
		t.Errorf("audit %v %v", f.audit.events, f.audit.fields)
	}

	// The command line's sign-in, as a bearer token: no CSRF token, no
	// cookie; via=remote-cli.
	cli := f.srv.Client()
	jack := f.idp.idToken(t, "jack", "approvals-cli", time.Hour)
	if code, body := do(t, cli, "GET", api+"session", map[string]string{"Authorization": "Bearer " + jack}); code != 200 ||
		!strings.Contains(body, `"name":"jack"`) || strings.Contains(body, "csrf") {
		t.Errorf("bearer session: %d %s", code, body)
	}
	if code, _ := do(t, cli, "DELETE", api+"instances/i-1", map[string]string{"Authorization": "Bearer " + jack}); code != 404 {
		t.Errorf("bearer action: %d", code)
	}
	if n := len(f.audit.fields); f.audit.fields[n-1]["via"] != ViaRemote {
		t.Errorf("bearer audit %v", f.audit.fields[n-1])
	}
	// A bearer token is taken alone: an agent's token, or another
	// client's, is refused even with the page's cookie.
	for name, tok := range map[string]string{
		"an agent's access token":    f.idp.idToken(t, "jack", "https://gw.example.com/mcp", time.Hour),
		"the page client's ID token": f.idp.idToken(t, "jack", "approvals", time.Hour),
		"not a bearer token":         "",
	} {
		h := "Bearer " + tok
		if tok == "" {
			h = "Basic amFjazp4"
		}
		if code, _ := do(t, c, "GET", api+"whoami", map[string]string{"Authorization": h}); code != 401 {
			t.Errorf("%s: %d", name, code)
		}
	}
}

// Without the control API the page serves no console.
func TestNoConsoleAPI(t *testing.T) {
	f := newFixture(t)
	c := f.browser(t)
	if code, _, _ := get(t, c, f.srv.URL+"/approvals/"); code != 200 {
		t.Fatal(code)
	}
	if code, _ := do(t, c, "GET", f.srv.URL+"/console/api/v1/whoami", nil); code != 404 {
		t.Errorf("%d", code)
	}
}
