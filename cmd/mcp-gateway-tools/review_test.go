package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/profile"
)

func TestReviewProfile(t *testing.T) {
	dir := t.TempDir()
	data, _ := json.Marshal(profile.DenialsFile{Domain: "mcpsrv_fw_t", Denials: []profile.Denial{
		{Source: "mcpsrv_fw_t", Target: "system_dbusd_t", Class: "unix_stream_socket", Perms: []string{"connectto"}},
		{Source: "firewalld_t", Target: "mcpsrv_fw_t", Class: "dbus", Perms: []string{"send_msg"}},
		{Source: "other_t", Target: "etc_t", Class: "file", Perms: []string{"read"}},
	}})
	if err := os.WriteFile(filepath.Join(dir, "denials.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := loadProfile(filepath.Join(dir, "denials.json"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Domain != "mcpsrv_fw_t" || !p.Targets["system_dbusd_t"] || !p.Targets["firewalld_t"] || p.Targets["etc_t"] || len(p.Targets) != 2 {
		t.Errorf("profile = %+v", p)
	}
}

func TestReviewRun(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "main.py"), []byte("import subprocess\nsubprocess.run(['snapper', 'list'])\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := runReview([]string{"--source", src}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "Programs it runs (1):") || !strings.Contains(out.String(), "main.py:2") {
		t.Errorf("report:\n%s", out.String())
	}
	out.Reset()
	if code := runReview([]string{"--source", src, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("json: exit %d", code)
	}
	var doc struct {
		Items []struct{ Kind, Value string }
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || len(doc.Items) != 1 || doc.Items[0].Value != "snapper" {
		t.Errorf("json %s: %v", out.String(), err)
	}
	for _, args := range [][]string{nil, {"--source", src, "extra"}, {"--source", src, "--profile", src}} {
		out.Reset()
		errOut.Reset()
		if code := runReview(args, &out, &errOut); code == 0 {
			t.Errorf("%v: exit 0", args)
		}
	}
}
