// Package profiles holds the server setups that the packages
// mcp-gateway-profile-<name> install (see README.md); this test checks
// them against the gateway's own validation.
package profiles

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/policydata"
)

var setups = []string{"systemd", "firewalld", "zypp", "suseconnect"}

// vendorDir returns a directory laid out like the installed
// /usr/share/mcp-gateway/servers.d with the definition of setup name.
func vendorDir(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(name, name+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name+".yaml"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDefinitions(t *testing.T) {
	for _, name := range setups {
		t.Run(name, func(t *testing.T) {
			bs, err := config.LoadBackends(vendorDir(t, name), t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			b := bs[name]
			if b == nil || len(bs) != 1 {
				t.Fatalf("definitions %v, want one named %q", bs, name)
			}
			if b.SELinuxType != "mcpsrv_"+name+"_t" || b.Privileged {
				t.Errorf("selinux_type %q, privileged %v", b.SELinuxType, b.Privileged)
			}
			for _, f := range []string{"mcp_" + name + ".te", "mcp_" + name + ".fc"} {
				if _, err := os.Stat(filepath.Join("..", "selinux", f)); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

// The privileged zypp variant is accepted from the administrator's
// directory (linked there), never as a vendor definition.
func TestZyppPrivileged(t *testing.T) {
	admin := t.TempDir()
	src, _ := filepath.Abs(filepath.Join("zypp", "zypp-privileged.yaml"))
	if err := os.Symlink(src, filepath.Join(admin, "zypp.yaml")); err != nil {
		t.Fatal(err)
	}
	bs, err := config.LoadBackends(vendorDir(t, "zypp"), admin)
	if err != nil {
		t.Fatal(err)
	}
	if !bs["zypp"].Privileged || bs["zypp"].RunAs != "root" {
		t.Errorf("zypp %+v", bs["zypp"])
	}
}

func TestRoles(t *testing.T) {
	shipped := t.TempDir()
	for _, name := range setups {
		data, err := os.ReadFile(filepath.Join(name, "roles.json"))
		if err != nil {
			t.Fatal(err)
		}
		problems, err := policydata.Check(data)
		if err != nil || len(problems) > 0 {
			t.Errorf("%s: %v %q", name, err, problems)
		}
		var d struct {
			Roles map[string]struct {
				Description string `json:"description"`
				Permissions []struct {
					Server string `json:"server"`
					Tool   string `json:"tool"`
				} `json:"permissions"`
			} `json:"roles"`
		}
		if err := json.Unmarshal(data, &d); err != nil {
			t.Fatal(err)
		}
		for role, r := range d.Roles {
			if !strings.HasPrefix(role, name+"-") || r.Description == "" {
				t.Errorf("%s: role %q needs the prefix %q and a description", name, role, name+"-")
			}
			for _, p := range r.Permissions {
				if p.Server != name {
					t.Errorf("%s: role %q grants on server %q", name, role, p.Server)
				}
			}
		}
		dir := filepath.Join(shipped, "mcp", "profiles", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "data.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// All setups installed together: no role shipped twice.
	roles, problems, err := policydata.ShippedRoles(shipped)
	if err != nil || len(problems) > 0 || len(roles) == 0 {
		t.Errorf("%v %q %v", err, problems, roles)
	}
}
