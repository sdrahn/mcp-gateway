package doctor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/webhook"
)

func TestWebhooks(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	var kinds []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if _, err := webhook.Verify([]byte(secret), body, r.Header.Get(webhook.SignatureHeader), time.Now()); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		kinds = append(kinds, r.Header.Get(webhook.EventHeader))
	}))
	defer srv.Close()
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	gw := &config.Gateway{}
	gw.HTTP.Listen, gw.HTTP.Audience = ":8443", "https://gw.example.com:8443/mcp"
	gw.Approvals.Webhooks = []config.Webhook{
		{Name: "chat", URL: srv.URL, SecretFile: write("chat", secret+"\n")},
		{Name: "wrong", URL: srv.URL, SecretFile: write("wrong", strings.Repeat("x", 40))},
		{Name: "short", URL: srv.URL, SecretFile: write("short", "abc")},
		{Name: "missing", URL: srv.URL, SecretFile: filepath.Join(dir, "none")},
		{Name: "down", URL: "https://127.0.0.1:1/", SecretFile: write("down", secret)},
		{Name: "exposed", URL: srv.URL, SecretFile: write("exposed", secret)},
	}
	exposed := gw.Approvals.Webhooks[5]
	if err := os.Chmod(exposed.SecretFile, 0o644); err != nil {
		t.Fatal(err)
	}
	rs := Webhooks(context.Background(), gw, srv.Client(), true)
	Identify(rs)
	want := map[string]struct {
		status Status
		text   string
	}{
		"webhook chat":    {OK, "decisions come back to https://gw.example.com:8443/approvals/webhook/chat"},
		"webhook wrong":   {Fail, "401 Unauthorized"},
		"webhook short":   {Fail, "holds 3 characters, fewer than 32"},
		"webhook missing": {Fail, "no such file"},
		"webhook down":    {Fail, "does not take a signed post"},
		"webhook exposed": {Fail, "may be read by others (mode 0644)"},
	}
	if len(rs) != len(want) {
		t.Fatalf("results %+v", rs)
	}
	for _, r := range rs {
		w := want[r.Check]
		if r.Status != w.status || !strings.Contains(r.Summary, w.text) || r.ID != "webhook" {
			t.Errorf("%s: %s %s (%s), want %s %q", r.Check, r.Status, r.Summary, r.ID, w.status, w.text)
		}
	}
	if len(kinds) != 1 || kinds[0] != "ping" {
		t.Errorf("posts %v", kinds)
	}
	// Without the listener: posts only.
	gw.HTTP = config.HTTP{}
	gw.Approvals.Webhooks = gw.Approvals.Webhooks[:1]
	if rs := Webhooks(context.Background(), gw, srv.Client(), true); rs[0].Status != Warn || !strings.Contains(rs[0].Summary, "decisions cannot come back") {
		t.Errorf("no listener: %+v", rs[0])
	}
	// Not root: the mode is checked all the same.
	if rs := Webhooks(context.Background(), &config.Gateway{Approvals: config.Approvals{Webhooks: []config.Webhook{exposed}}}, srv.Client(), false); rs[0].Status != Fail {
		t.Errorf("exposed, not root: %+v", rs[0])
	}
	// Not root: the secret is not readable.
	if rs := Webhooks(context.Background(), gw, srv.Client(), false); rs[0].Status != Skip || !strings.Contains(rs[0].Summary, "needs root") {
		t.Errorf("not root: %+v", rs[0])
	}
}
