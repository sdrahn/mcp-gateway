package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/landlock"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Instance is a running backend. Reads and writes are the backend's
// stdout and stdin; Close stops it.
type Instance interface {
	io.ReadWriteCloser
	// Name identifies the instance in logs (e.g. the unit name).
	Name() string
}

// Launcher starts backend instances. id identifies the instance (lower-case
// hex); it appears in unit names.
type Launcher interface {
	Start(ctx context.Context, b *config.Backend, p principal.Principal, id string) (Instance, error)
}

// plainUser is a ${USER} that may go into a command line, a path or an
// environment variable: a local account's name, or a token subject of
// letters, digits and ._@- that cannot climb out of a path.
var plainUser = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._@-]{0,63}$`)

// usesUser reports whether b's command, environment or Landlock rules
// name ${USER}.
func usesUser(b *config.Backend) bool {
	has := func(s string) bool { return strings.Contains(s, "${USER}") || strings.Contains(s, "$USER") }
	for _, a := range b.Command {
		if has(a) {
			return true
		}
	}
	for _, v := range b.Env {
		if has(v) {
			return true
		}
	}
	found := false
	if b.Landlock != nil {
		b.Landlock.Expand(func(s string) string { found = found || has(s); return s })
	}
	return found
}

// CheckUser refuses to start b for p when b names ${USER} and p's
// subject is not plain: a remote principal's subject is the identity
// provider's (security review, 1.11).
func CheckUser(b *config.Backend, p principal.Principal) error {
	if usesUser(b) && (strings.Contains(p.Sub, "..") || !plainUser.MatchString(p.Sub)) {
		return fmt.Errorf("supervisor: server %s names ${USER}, and the principal's name %q is not one that may go into a command or a path (letters, digits and ._@-)", b.Name, p.Sub)
	}
	return nil
}

// ExpandVars is expandVars, for the router's requires.
func ExpandVars(s string, p principal.Principal) string { return expandVars(s, p) }

// expandVars substitutes ${HOME}, ${USER} and ${UID} (the principal's)
// in s and leaves every other ${...} untouched. ${UID} is empty for a
// principal without a local account; environment and landlockRules leave
// out what names it then.
func expandVars(s string, p principal.Principal) string {
	return os.Expand(s, func(k string) string {
		switch k {
		case "HOME":
			return p.Home
		case "USER":
			return p.Sub
		case "UID":
			if p.UID == nil {
				return ""
			}
			return strconv.FormatUint(uint64(*p.UID), 10)
		}
		return "${" + k + "}"
	})
}

// command returns the backend's command line for p: through
// mcp-landlock with the definition's rules, if it has landlock.
func command(b *config.Backend, p principal.Principal) []string {
	out := make([]string, len(b.Command))
	for i, a := range b.Command {
		out[i] = expandVars(a, p)
	}
	if b.Landlock == nil {
		return out
	}
	rules, _ := json.Marshal(landlockRules(*b.Landlock, p))
	return append([]string{config.LandlockLauncher, "-rules", string(rules), "--"}, out...)
}

// landlockRules are the definition's rules for p. A tree that expands
// to / (the home of the discovery instance, which runs for no one) is
// read, never written.
func landlockRules(r landlock.Rules, p principal.Principal) landlock.Rules {
	if p.UID == nil {
		r = r.Without(namesUID)
	}
	r = r.Expand(func(s string) string { return expandVars(s, p) })
	var write []string
	for _, w := range r.Write {
		if path.Clean(w) == "/" {
			r.Read = append(r.Read, "/")
			continue
		}
		write = append(write, w)
	}
	r.Write = write
	return r
}

// PrincipalEnv is the variable that tells an instance whom it serves
// (docs/user-guide/04-mcp-servers.md, "Whom an instance serves"). The
// gateway sets it; a definition may not (config.ReservedEnvPrefix).
const PrincipalEnv = "MCP_GATEWAY_PRINCIPAL"

// principalInfo is PrincipalEnv's value, in this field order.
type principalInfo struct {
	Kind string  `json:"kind"`
	Sub  string  `json:"sub,omitempty"`
	Iss  string  `json:"iss,omitempty"`
	UID  *uint32 `json:"uid,omitempty"`
}

// PrincipalValue is PrincipalEnv's value for an instance of p: compact
// JSON naming the kind (local: a local client on the Unix socket; remote:
// a client with a token over HTTP), the subject, the issuer of a remote
// principal and the local uid when there is one. An instance that runs
// for no one (the shared discovery instance, inspect) gets
// {"kind":"none"}. Nothing else of the principal: no token, claims,
// groups, scopes or roles. It informs the backend and grants nothing.
func PrincipalValue(p principal.Principal) string {
	var info principalInfo
	switch p.Transport {
	case principal.TransportUnix:
		info = principalInfo{Kind: "local", Sub: p.Sub, UID: p.UID}
	case principal.TransportHTTP:
		info = principalInfo{Kind: "remote", Sub: p.Sub, Iss: p.Issuer, UID: p.UID}
	default:
		info = principalInfo{Kind: "none"}
	}
	out, _ := json.Marshal(info)
	return string(out)
}

// environment returns the backend's environment for p: a minimal base plus
// the backend's own variables, sorted for determinism. PrincipalEnv is the
// gateway's: set after the definition's, it wins (config refuses a
// definition that names it).
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
		if p.UID == nil && namesUID(v) {
			continue // no uid: XDG_RUNTIME_DIR=/run/user/ would mislead
		}
		env[k] = expandVars(v, p)
	}
	env[PrincipalEnv] = PrincipalValue(p)
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// namesUID reports whether s names ${UID}.
func namesUID(s string) bool { return strings.Contains(s, "${UID}") }

// unitName returns the transient unit name for an instance; it must match
// the polkit rule in packaging/polkit/50-mcp-gateway.rules.
func unitName(b *config.Backend, id string) string {
	return fmt.Sprintf("mcp-%s-%s.service", b.Name, strings.ToLower(id))
}
