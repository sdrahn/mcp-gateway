package supervisor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

func alice() principal.Principal {
	uid := uint32(1001)
	return principal.Principal{Sub: "alice", UID: &uid, Home: "/home/alice", SessionID: "0123456789abcdef"}
}

func TestCommandAndEnvironment(t *testing.T) {
	b := &config.Backend{
		Name:    "fs",
		Command: []string{"/usr/bin/fs", "--root", "${HOME}", "--keep", "${OTHER}"},
		Env:     map[string]string{"FOO": "${USER}-x"},
	}
	got := command(b, alice())
	want := []string{"/usr/bin/fs", "--root", "/home/alice", "--keep", "${OTHER}"}
	if !slices.Equal(got, want) {
		t.Errorf("command = %q", got)
	}
	env := environment(b, alice())
	for _, kv := range []string{"FOO=alice-x", "HOME=/home/alice", "USER=alice"} {
		if !slices.Contains(env, kv) {
			t.Errorf("environment %q lacks %q", env, kv)
		}
	}
	if !slices.IsSorted(env) {
		t.Errorf("environment not sorted: %q", env)
	}
	if n := unitName(b, "0123456789abcdef"); n != "mcp-fs-0123456789abcdef.service" {
		t.Errorf("unit name %q", n)
	}
}

func TestMCSAllocator(t *testing.T) {
	a := NewMCSAllocator(0, 3) // 6 pairs
	seen := map[string]bool{}
	for range 6 {
		p, err := a.Allocate()
		if err != nil {
			t.Fatal(err)
		}
		var x, y int
		if _, err := fmt.Sscanf(p, "c%d,c%d", &x, &y); err != nil || x >= y || x < 0 || y > 3 {
			t.Fatalf("bad pair %q", p)
		}
		if seen[p] {
			t.Fatalf("duplicate pair %q", p)
		}
		seen[p] = true
	}
	if _, err := a.Allocate(); err != ErrMCSExhausted {
		t.Fatalf("want ErrMCSExhausted, got %v", err)
	}
	a.Release("c0,c1")
	if p, err := a.Allocate(); err != nil || p != "c0,c1" {
		t.Fatalf("after release: %q %v", p, err)
	}
}

func propMap(t *testing.T, s *Systemd, b *config.Backend, p principal.Principal, mcs string) map[string]any {
	t.Helper()
	props, err := s.Properties(b, p, 5, mcs)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	for _, pr := range props {
		m[pr.Name] = pr.Value.Value()
	}
	return m
}

func TestSystemdProperties(t *testing.T) {
	s := &Systemd{}
	b := &config.Backend{Name: "fs", Command: []string{"/usr/bin/fs"}, SELinuxType: "mcpsrv_fs_t",
		RunAs: "principal", Sandbox: config.Sandbox{ProtectHome: "read-write"}}
	m := propMap(t, s, b, alice(), "c3,c7")
	if m["User"] != "alice" || m["ProtectHome"] != "no" || m["PrivateNetwork"] != true {
		t.Errorf("props %v", m)
	}
	// stderr to the journal, not duplicated from stdout (the socket).
	if m["StandardOutput"] != "null" || m["StandardError"] != "journal" {
		t.Errorf("StandardOutput %v, StandardError %v", m["StandardOutput"], m["StandardError"])
	}
	if m["SELinuxContext"] != "system_u:system_r:mcpsrv_fs_t:s0:c3,c7" {
		t.Errorf("SELinuxContext %v", m["SELinuxContext"])
	}
	if _, ok := m["RestrictAddressFamilies"]; !ok {
		t.Error("RestrictAddressFamilies missing")
	}
	for k, want := range map[string]any{"CapabilityBoundingSet": uint64(0), "NoNewPrivileges": true,
		"RestrictSUIDSGID": true, "ProtectSystem": "strict", "UMask": uint32(0o077)} {
		if m[k] != want {
			t.Errorf("%s = %v, want %v", k, m[k], want)
		}
	}
	if _, ok := m["SystemCallFilter"]; !ok {
		t.Error("SystemCallFilter missing")
	}
	if p, ok := m["InaccessiblePaths"].([]string); !ok || len(p) != 1 || p[0] != "-/run/systemd/transient" {
		t.Errorf("InaccessiblePaths %v", m["InaccessiblePaths"])
	}
	for _, k := range []string{"ReadWritePaths", "StateDirectory"} {
		if _, ok := m[k]; ok {
			t.Errorf("unexpected %s without sandbox settings", k)
		}
	}

	b.Sandbox.ReadWritePaths = []string{"/var/lib/fs"}
	b.Sandbox.StateDirectory = "fs"
	m = propMap(t, s, b, alice(), "c3,c7")
	if rw, _ := m["ReadWritePaths"].([]string); len(rw) != 1 || rw[0] != "/var/lib/fs" {
		t.Errorf("ReadWritePaths %v", m["ReadWritePaths"])
	}
	if sd, _ := m["StateDirectory"].([]string); len(sd) != 1 || sd[0] != "fs" || m["StateDirectoryMode"] != uint32(0o700) {
		t.Errorf("StateDirectory %v mode %v", m["StateDirectory"], m["StateDirectoryMode"])
	}
	b.Sandbox.ReadWritePaths, b.Sandbox.StateDirectory = nil, ""

	b.Network, b.RunAs = true, "dynamic"
	m = propMap(t, s, b, alice(), "")
	if m["DynamicUser"] != true || m["PrivateNetwork"] != false {
		t.Errorf("props %v", m)
	}
	for _, k := range []string{"User", "SELinuxContext", "RestrictAddressFamilies"} {
		if _, ok := m[k]; ok {
			t.Errorf("unexpected %s", k)
		}
	}

	// A remote principal without a local account gets a dynamic user.
	b.RunAs = "principal"
	remote := principal.Principal{Sub: "bob@idp", SessionID: "x"}
	m = propMap(t, s, b, remote, "c1,c2")
	if m["DynamicUser"] != true || m["User"] != nil {
		t.Errorf("remote props %v", m)
	}
}

func TestSystemdPropertiesPrivileged(t *testing.T) {
	s := &Systemd{SELinux: true}
	b := &config.Backend{Name: "zypp", Command: []string{"/usr/bin/mcp-server-zypp"}, SELinuxType: "mcpsrv_zypp_t",
		RunAs: "root", Network: true, Privileged: true, Sandbox: config.Sandbox{ProtectHome: "read-only"}}
	m := propMap(t, s, b, alice(), "")
	if m["User"] != "root" || m["NoNewPrivileges"] != false || m["UMask"] != uint32(0o022) || m["PrivateNetwork"] != false {
		t.Errorf("props %v", m)
	}
	if m["SELinuxContext"] != "system_u:system_r:mcpsrv_zypp_t:s0" {
		t.Errorf("SELinuxContext %v", m["SELinuxContext"])
	}
	for _, k := range []string{"ProtectSystem", "ProtectHome", "CapabilityBoundingSet", "SystemCallFilter",
		"RestrictSUIDSGID", "PrivateDevices", "RestrictAddressFamilies", "ReadWritePaths"} {
		if _, ok := m[k]; ok {
			t.Errorf("unexpected %s on a privileged instance", k)
		}
	}
	s.SELinux = false
	if m = propMap(t, s, b, alice(), ""); m["SELinuxContext"] != nil {
		t.Errorf("SELinuxContext without SELinux: %v", m["SELinuxContext"])
	}
}

func TestExecLauncher(t *testing.T) {
	if _, err := os.Stat("/bin/cat"); err != nil {
		t.Skip("no /bin/cat")
	}
	uid := uint32(os.Getuid())
	p := principal.Principal{Sub: "me", UID: &uid, SessionID: "feedfacefeedface"}
	b := &config.Backend{Name: "cat", Command: []string{"/bin/cat"}, RunAs: "gateway"}
	inst, err := (&Exec{}).Start(context.Background(), b, p, "feedfacefeedface")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inst.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(inst).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "hello" {
		t.Fatalf("got %q, %v", line, err)
	}
	if err := inst.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSystemdLoadCredential(t *testing.T) {
	b := &config.Backend{Name: "git", Command: []string{"/usr/bin/git-mcp"}, SELinuxType: "mcpsrv_generic_t",
		RunAs: "principal", Sandbox: config.Sandbox{ProtectHome: "read-only"},
		Credentials: []string{"github-token", "db:/srv/db.pass"}}
	m := propMap(t, &Systemd{}, b, alice(), "")
	got := fmt.Sprint(m["LoadCredential"])
	want := "[{github-token " + config.DefaultCredentialsDir + "/github-token} {db /srv/db.pass}]"
	if got != want {
		t.Fatalf("LoadCredential = %s, want %s", got, want)
	}
}

func TestExecCredentials(t *testing.T) {
	src := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(src, []byte("s3cr3t"), 0o600); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	p := principal.Principal{Sub: "me", UID: &uid, SessionID: "cafe"}
	// The "server" prints its credential and where it found it, then exits.
	b := &config.Backend{Name: "sh", Command: []string{"/bin/sh", "-c", `cat "$CREDENTIALS_DIRECTORY/token"; echo; echo "$CREDENTIALS_DIRECTORY"`},
		RunAs: "gateway", Credentials: []string{"token:" + src}}
	inst, err := (&Exec{}).Start(context.Background(), b, p, "cafecafecafecafe")
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(inst)
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 || lines[0] != "s3cr3t" {
		t.Fatalf("output %q", out)
	}
	_ = inst.Close()
	if _, err := os.Stat(lines[1]); !os.IsNotExist(err) {
		t.Fatalf("credentials directory %s not removed: %v", lines[1], err)
	}
}

// Output written right before the process exits must not be lost (Wait
// used to close the pipe under the reader).
func TestExecOutputBeforeExit(t *testing.T) {
	uid := uint32(os.Getuid())
	p := principal.Principal{Sub: "me", UID: &uid, SessionID: "beef"}
	b := &config.Backend{Name: "sh", Command: []string{"/bin/sh", "-c", "seq 1 20000"}, RunAs: "gateway"}
	for range 20 {
		inst, err := (&Exec{}).Start(context.Background(), b, p, "beefbeefbeefbeef")
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond) // let the process exit first
		out, _ := io.ReadAll(inst)
		_ = inst.Close()
		if !strings.HasSuffix(string(out), "\n20000\n") {
			t.Fatalf("output truncated to %d bytes", len(out))
		}
	}
}

func TestHasSELinuxFS(t *testing.T) {
	with := `22 26 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:2 - sysfs sysfs rw
24 22 0:22 / /sys/fs/selinux rw,nosuid,noexec,relatime shared:3 - selinuxfs selinuxfs rw
`
	without := `22 26 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:2 - sysfs sysfs rw
30 22 0:26 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime shared:7 - securityfs securityfs rw
`
	if !hasSELinuxFS(strings.NewReader(with)) {
		t.Error("selinuxfs mount not found")
	}
	if hasSELinuxFS(strings.NewReader(without)) {
		t.Error("selinuxfs found where there is none")
	}
}
