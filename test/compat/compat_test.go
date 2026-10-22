// Package compat checks that the gateway reads the configuration of the
// previous minor release: gateway.yaml, server definitions and role data,
// as snapshot.sh took them from its tag (docs/architecture.md, decision
// D10). Deprecated keys are allowed; they are logged as warnings.
package compat

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
			_, data, _, err := policydata.Read(filepath.Join(dir, "policy", "rbac", "data.json"))
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

// The snapshot is of the minor release before the one this tree builds
// (the spec's Version): the latest earlier one CHANGELOG.md names. Main
// moves to the next minor in the commit that records a release, which
// takes the new snapshot too; tools/check-release checks the same
// before a minor release is tagged.
func TestSnapshotIsPreviousMinor(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("..", "..", "packaging", "suse", "mcp-gateway.spec"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^Version:\s*(\d+)\.(\d+)\.\d+`).FindSubmatch(spec)
	if m == nil {
		t.Fatal("no Version in the spec")
	}
	building := [2]int{atoi(t, string(m[1])), atoi(t, string(m[2]))}
	changelog, err := os.ReadFile(filepath.Join("..", "..", "CHANGELOG.md"))
	if err != nil {
		t.Fatal(err)
	}
	var previous [2]int
	found := false
	for _, h := range regexp.MustCompile(`(?m)^## v(\d+)\.(\d+)\.\d+ `).FindAllSubmatch(changelog, -1) {
		v := [2]int{atoi(t, string(h[1])), atoi(t, string(h[2]))}
		if less(v, building) && (!found || less(previous, v)) {
			previous, found = v, true
		}
	}
	if !found {
		t.Fatal("CHANGELOG.md names no earlier release")
	}
	want := fmt.Sprintf("%d.%d", previous[0], previous[1])
	if _, err := os.Stat(filepath.Join(want, "TAG")); err != nil {
		t.Fatalf("no snapshot of %s, the minor release before %d.%d: run test/compat/snapshot.sh v%s.<latest> and remove the older one",
			want, building[0], building[1], want)
	}
}

func less(a, b [2]int) bool { return a[0] < b[0] || a[0] == b[0] && a[1] < b[1] }

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
