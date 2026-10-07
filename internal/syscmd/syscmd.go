// Package syscmd finds system programs that live in sbin directories.
//
// MCP servers get a minimal PATH without /usr/sbin (supervisor), and so
// does the gateway-admin server, whose checks run tools that SUSE
// installs there: matchpathcon and restorecon (selinux-tools,
// policycoreutils), ausearch (audit), semanage. Path finds them anyway.
package syscmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Dirs are searched after PATH.
var Dirs = []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"}

// ErrNotFound is returned (wrapped) when a program is in none of them.
var ErrNotFound = errors.New("not found")

// Path returns the program name from PATH, else from Dirs.
func Path(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, d := range Dirs {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: %w in PATH or %v", name, ErrNotFound, Dirs)
}
