package main

import (
	"errors"
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

func TestForeignFilesUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	if _, err := foreignFiles(dir, uint32(os.Geteuid())); !errors.Is(err, os.ErrPermission) {
		t.Errorf("unreadable directory: %v", err)
	}
}
