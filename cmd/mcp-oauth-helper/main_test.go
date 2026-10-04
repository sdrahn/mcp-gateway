package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/oauth"
)

func TestRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	in := `{"op":"token","url":"http://localhost:` + port + `/token","grant_type":"refresh_token","refresh_token":"x"}` + "\n"
	var out, errb strings.Builder
	if rc := run(context.Background(), []string{"-resolve", "localhost:" + port + ":127.0.0.1"}, strings.NewReader(in), &out, &errb); rc != 0 {
		t.Fatalf("rc %d: %s", rc, errb.String())
	}
	var r oauth.Response
	if err := json.Unmarshal([]byte(out.String()), &r); err != nil || !oauth.IsInvalidGrant(r.Err()) {
		t.Errorf("answer %q: %v", out.String(), err)
	}
	if strings.Contains(errb.String(), `"x"`) {
		t.Errorf("stderr shows the request: %s", errb.String())
	}

	out.Reset()
	if rc := run(context.Background(), nil, strings.NewReader("not json\n"), &out, &errb); rc != 0 || !strings.Contains(out.String(), "malformed request") {
		t.Errorf("malformed: %d %q", rc, out.String())
	}
	if rc := run(context.Background(), []string{"-proxy", "socks5://x"}, strings.NewReader(""), &out, &errb); rc != 2 {
		t.Errorf("bad proxy: %d", rc)
	}
}
