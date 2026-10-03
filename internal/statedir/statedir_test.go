package statedir

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestForeignFilesUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	if _, err := ForeignFiles(dir, uint32(os.Geteuid())); !errors.Is(err, os.ErrPermission) {
		t.Errorf("unreadable directory: %v", err)
	}
}
