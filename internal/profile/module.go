package profile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DevelMakefile builds policy modules (selinux-policy-devel).
const DevelMakefile = "/usr/share/selinux/devel/Makefile"

// Build compiles module name from te and fc in dir (written there as
// name.te, name.fc and an empty name.if) and returns the path of the
// package.
func Build(ctx context.Context, dir, name, te, fc string) (string, error) {
	if _, err := os.Stat(DevelMakefile); err != nil {
		return "", fmt.Errorf("building a policy module needs %s (package selinux-policy-devel)", DevelMakefile)
	}
	for ext, content := range map[string]string{".te": te, ".fc": fc, ".if": ""} {
		if err := os.WriteFile(filepath.Join(dir, name+ext), []byte(content), 0o644); err != nil {
			return "", err
		}
	}
	out, err := run(ctx, dir, "make", "-f", DevelMakefile, name+".pp")
	if err != nil {
		return "", fmt.Errorf("building %s: %w\n%s", name, err, out)
	}
	return filepath.Join(dir, name+".pp"), nil
}

// Install loads a policy package.
func Install(ctx context.Context, pp string) error {
	if out, err := run(ctx, "", "semodule", "-i", pp); err != nil {
		return fmt.Errorf("loading %s: %w\n%s", filepath.Base(pp), err, out)
	}
	return nil
}

// Remove unloads module name.
func Remove(ctx context.Context, name string) error {
	if out, err := run(ctx, "", "semodule", "-r", name); err != nil {
		return fmt.Errorf("removing %s: %w\n%s", name, err, out)
	}
	return nil
}

// Relabel restores the file context of path.
func Relabel(ctx context.Context, path string) error {
	if path == "" {
		return nil
	}
	if out, err := run(ctx, "", "restorecon", "-F", path); err != nil {
		return fmt.Errorf("restorecon %s: %w\n%s", path, err, out)
	}
	return nil
}

// Loaded reports whether module name is loaded.
func Loaded(ctx context.Context, name string) bool {
	out, err := run(ctx, "", "semodule", "-l")
	if err != nil {
		return false
	}
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == name {
			return true
		}
	}
	return false
}

func run(ctx context.Context, dir, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		err = fmt.Errorf("%s exited with %d", name, ee.ExitCode())
	}
	return strings.TrimSpace(string(out)), err
}
