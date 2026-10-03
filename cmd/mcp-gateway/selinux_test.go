package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

func TestWarnMissingSELinuxTypes(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	backends := map[string]*config.Backend{
		"zypp": {Name: "zypp", SELinuxType: "mcpsrv_zypp_t"},
		"fs":   {Name: "fs", SELinuxType: "mcpsrv_fs_t"},
	}
	warnMissingSELinuxTypes(log, backends, func(ctx string) (bool, error) {
		return ctx == "system_u:system_r:mcpsrv_fs_t:s0", nil
	})
	out := buf.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "selinux_type=mcpsrv_zypp_t servers=zypp") ||
		strings.Contains(out, "mcpsrv_fs_t") {
		t.Fatalf("log: %s", out)
	}
}
