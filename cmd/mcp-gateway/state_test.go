package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestRefuseRoot(t *testing.T) {
	exists := func(string) (*user.User, error) { return &user.User{Uid: "475"}, nil }
	missing := func(string) (*user.User, error) { return nil, user.UnknownUserError(gatewayUser) }
	if err := refuseRoot(0, false, exists); err == nil || !strings.Contains(err.Error(), "-allow-root") {
		t.Errorf("root with the service account: %v", err)
	}
	for name, err := range map[string]error{
		"-allow-root": refuseRoot(0, true, exists),
		"no account":  refuseRoot(0, false, missing),
		"not root":    refuseRoot(1000, false, exists),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCheckStateOwnership(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pending.json"), []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	uid := os.Geteuid()
	if uid == 0 {
		t.Skip("as root, every file is checked against root")
	}
	if err := checkStateOwnership(dir, uid); err != nil {
		t.Fatalf("own files: %v", err)
	}
	// As another user, the files are foreign.
	err := checkStateOwnership(dir, uid+1)
	if err == nil || !strings.Contains(err.Error(), filepath.Join(dir, "pending.json")) ||
		!strings.Contains(err.Error(), "chown -R") {
		t.Fatalf("foreign files: %v", err)
	}
	if err := checkStateOwnership(filepath.Join(dir, "missing"), uid); err != nil {
		t.Errorf("missing directory: %v", err)
	}
	if err := checkStateOwnership(dir, 0); err != nil {
		t.Errorf("root: %v", err)
	}
}

// Container mode: the state volume's root may be the platform's; the
// files in it must still be the gateway's.
func TestCheckStateVolume(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give files to other users")
	}
	const gw = 10001
	dir := t.TempDir() // root's, as a volume's root is
	if err := checkStateVolume(dir, gw); err != nil {
		t.Errorf("a root-owned volume root: %v", err)
	}
	if err := checkStateOwnership(dir, gw); err == nil {
		t.Error("checkStateOwnership accepted a root-owned state directory")
	}
	f := filepath.Join(dir, "grants.json")
	if err := os.WriteFile(f, []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkStateVolume(dir, gw); err == nil || !strings.Contains(err.Error(), f) {
		t.Errorf("a file of root's in the volume: %v", err)
	}
	if err := os.Chown(f, gw, gw); err != nil {
		t.Fatal(err)
	}
	if err := checkStateVolume(dir, gw); err != nil {
		t.Errorf("the gateway's file: %v", err)
	}
	if err := checkStateVolume(filepath.Join(dir, "missing"), gw); err != nil {
		t.Errorf("missing directory: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the write check left files: %v", entries)
	}
}
