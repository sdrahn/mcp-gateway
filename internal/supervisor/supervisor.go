package supervisor

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Instance is a running backend. Reads and writes are the backend's
// stdout and stdin; Close stops it.
type Instance interface {
	io.ReadWriteCloser
	// Name identifies the instance in logs (e.g. the unit name).
	Name() string
}

// Launcher starts backend instances.
type Launcher interface {
	Start(ctx context.Context, b *config.Backend, p principal.Principal) (Instance, error)
}

// expandVars substitutes ${HOME} and ${USER} (the principal's) in s and
// leaves every other ${...} untouched.
func expandVars(s string, p principal.Principal) string {
	return os.Expand(s, func(k string) string {
		switch k {
		case "HOME":
			return p.Home
		case "USER":
			return p.Sub
		}
		return "${" + k + "}"
	})
}

// command returns the backend's command line for p.
func command(b *config.Backend, p principal.Principal) []string {
	out := make([]string, len(b.Command))
	for i, a := range b.Command {
		out[i] = expandVars(a, p)
	}
	return out
}

// environment returns the backend's environment for p: a minimal base plus
// the backend's own variables, sorted for determinism.
func environment(b *config.Backend, p principal.Principal) []string {
	env := map[string]string{
		"PATH": "/usr/local/bin:/usr/bin",
		"LANG": "C.UTF-8",
	}
	if p.Home != "" {
		env["HOME"] = p.Home
	}
	if p.UID != nil {
		env["USER"] = p.Sub
	}
	for k, v := range b.Env {
		env[k] = expandVars(v, p)
	}
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// unitName returns the transient unit name for an instance; it must match
// the polkit rule in packaging/polkit/50-mcp-gateway.rules.
func unitName(b *config.Backend, p principal.Principal) string {
	return fmt.Sprintf("mcp-%s-%s.service", b.Name, strings.ToLower(p.SessionID))
}
