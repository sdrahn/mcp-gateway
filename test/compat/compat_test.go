// Package compat checks that the gateway reads the configuration of the
// previous minor release: gateway.yaml, server definitions and role data,
// as snapshot.sh took them from its tag (docs/architecture.md, decision
// D10). Deprecated keys are allowed; they are logged as warnings.
package compat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/policydata"
)

func TestPreviousRelease(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join("*", "TAG"))
	if err != nil {
		t.Fatal(err)
	}
	if len(dirs) == 0 {
		t.Fatal("no snapshot: run snapshot.sh with the previous release's tag")
	}
	for _, tagFile := range dirs {
		dir := filepath.Dir(tagFile)
		t.Run(dir, func(t *testing.T) {
			g, err := config.LoadGateway(filepath.Join(dir, "gateway.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range g.Warnings {
				t.Log("gateway.yaml:", w)
			}

			bs, err := config.LoadBackends(filepath.Join(dir, "servers.d"), filepath.Join(dir, "admin-servers.d"))
			if err != nil {
				t.Fatal(err)
			}
			if len(bs) == 0 {
				t.Error("no server definitions")
			}
			for name, b := range bs {
				for _, w := range b.Warnings {
					t.Logf("server %s: %s", name, w)
				}
			}

			shipped, problems, err := policydata.ShippedRoles(filepath.Join(dir, "policy"))
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(dir, "policy", "rbac", "data.json"))
			if err != nil {
				t.Fatal(err)
			}
			own, err := policydata.CheckWith(data, shipped)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range append(problems, own...) {
				t.Error("role data:", p)
			}
		})
	}
}
