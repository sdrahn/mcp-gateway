package main

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// fileType returns the SELinux type of the file path names (symlinks
// followed: systemd runs the target).
func fileType(path string) (string, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("%s: not found", path)
	}
	buf := make([]byte, 256)
	n, err := unix.Getxattr(real, "security.selinux", buf)
	if err != nil {
		return "", fmt.Errorf("%s: reading its label: %w", real, err)
	}
	return contextType(strings.TrimRight(string(buf[:n]), "\x00")), nil
}

// policyType returns the SELinux type the loaded policy gives path, from
// matchpathcon, else from a dry run of restorecon.
func policyType(path string) (string, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if out, err := exec.Command("matchpathcon", "-n", real).Output(); err == nil {
		return contextType(strings.TrimSpace(string(out))), nil
	}
	out, err := exec.Command("restorecon", "-n", "-v", "-F", real).CombinedOutput()
	if err != nil {
		return "", errors.New("neither matchpathcon nor restorecon could tell (install selinux-tools)")
	}
	// "Would relabel PATH from CONTEXT to CONTEXT"; nothing if it matches.
	if _, to, ok := strings.Cut(string(out), " to "); ok {
		return contextType(strings.TrimSpace(to)), nil
	}
	if strings.TrimSpace(string(out)) != "" {
		return "", fmt.Errorf("restorecon: %s", strings.TrimSpace(string(out)))
	}
	return fileType(real)
}

// contextType is the type of a context user:role:type:level.
func contextType(ctx string) string {
	if parts := strings.SplitN(ctx, ":", 4); len(parts) >= 3 {
		return parts[2]
	}
	return ctx
}

// readOnly reports whether path is on a read-only file system (/usr of
// a transactional system). Not meaningful inside the gateway's own
// sandbox, which mounts /usr read-only; the doctor runs outside it.
func readOnly(path string) bool {
	var st unix.Statfs_t
	return unix.Statfs(path, &st) == nil && st.Flags&unix.ST_RDONLY != 0
}
