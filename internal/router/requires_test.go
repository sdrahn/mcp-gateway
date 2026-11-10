package router

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// A server with requires is offered only to principals for whom the
// paths exist (#348): to the others it is left out of the tool list, a
// call is refused naming the missing path, and no instance is started
// for them. The shared discovery instance, for no principal, needs none.
func TestRequiresLeavesServerOut(t *testing.T) {
	for _, discovery := range []string{config.DiscoveryShared, config.DiscoveryInstance} {
		t.Run(discovery, func(t *testing.T) {
			r, l := sharedRouter(t)
			run := t.TempDir()
			if err := os.MkdirAll(filepath.Join(run, "1001", "podman"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(run, "1001", "podman", "podman.sock"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
			r.Backends["fs"].Discovery = discovery
			r.Backends["fs"].Requires = []string{filepath.Join(run, "${UID}", "podman", "podman.sock")}

			// bob (1002) has no socket.
			b := connect(t, r, bob(), "", nil)
			got := names(t, b.roundTrip(1, "tools/list", map[string]any{}), "tools", "name")
			if slices.ContainsFunc(got, func(n string) bool { return strings.HasPrefix(n, "fs__") }) || !slices.Contains(got, "tmp__read_file") {
				t.Errorf("bob's tools %v", got)
			}
			m := b.roundTrip(2, "tools/call", map[string]any{"name": "fs__read_file", "arguments": map[string]any{}})
			want := "server fs needs " + filepath.Join(run, "1002", "podman", "podman.sock") + ", which does not exist"
			if m.Error == nil || !strings.Contains(m.Error.Message, want) {
				t.Errorf("bob's call: %+v, want %q", m, want)
			}
			// A principal without a uid has no such path either.
			z := connect(t, r, zed(), "", nil)
			m = z.roundTrip(1, "tools/call", map[string]any{"name": "fs__read_file", "arguments": map[string]any{}})
			if m.Error == nil || !strings.Contains(m.Error.Message, "/${UID}/podman/podman.sock, which does not exist") {
				t.Errorf("zed's call: %+v", m)
			}
			for _, fi := range l.started("fs") {
				if fi.p.Sub == "bob" || fi.p.Sub == "zed" {
					t.Errorf("an instance started for %s", fi.p.Sub)
				}
			}

			// alice (1001) has one: as before.
			a := connect(t, r, alice(), "", nil)
			got = names(t, a.roundTrip(1, "tools/list", map[string]any{}), "tools", "name")
			if !slices.Contains(got, "fs__read_file") {
				t.Errorf("alice's tools %v", got)
			}
			if text, isErr := toolText(t, a.roundTrip(2, "tools/call", map[string]any{"name": "fs__read_file", "arguments": map[string]any{}})); isErr {
				t.Errorf("alice's call: %s", text)
			}
		})
	}
}

func TestNotOffered(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	b := &config.Backend{Name: "x"}
	for _, tc := range []struct {
		req  string
		want string // "" offered
	}{
		{file, ""},
		{filepath.Join(dir, "${USER}"), "server x needs " + filepath.Join(dir, "alice") + ", which does not exist"},
		{filepath.Join(file, "below"), "server x needs " + filepath.Join(file, "below") + ", which does not exist"}, // ENOTDIR
	} {
		b.Requires = []string{tc.req}
		err := notOffered(b, alice())
		if (err == nil) != (tc.want == "") || (err != nil && err.Error() != tc.want) {
			t.Errorf("%s: %v, want %q", tc.req, err, tc.want)
		}
	}
	// The discovery instance needs none.
	b.Requires = []string{filepath.Join(dir, "${UID}")}
	if err := notOffered(b, discoveryPrincipal); err != nil {
		t.Errorf("discovery: %v", err)
	}
}
