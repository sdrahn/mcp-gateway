package router

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"syscall"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
)

// MissingPathError is returned for a server with requires
// (config.Backend.Requires) and a principal for whom one of those paths
// does not exist: the server cannot work for it (the user's Podman
// socket of a user without rootless Podman), so it is not offered and no
// instance is started.
type MissingPathError struct {
	Server string
	Path   string
}

func (e *MissingPathError) Error() string {
	return fmt.Sprintf("server %s needs %s, which does not exist", e.Server, e.Path)
}

// notOffered says why b is not offered to pr: it works in the home and
// pr has none (*NoHomeError), or a path it requires does not exist for
// pr (*MissingPathError); nil if it is offered. A required path naming
// ${UID} does not exist for a principal without a local account. The
// gateway looks as its own account: a path it cannot reach for another
// reason (a directory it may not enter) counts as present, and the
// instance tells. The shared discovery instance needs none of them.
func notOffered(b *config.Backend, pr principal.Principal) error {
	if pr.Home == "" && b.NeedsHome() {
		return &NoHomeError{Server: b.Name}
	}
	if isDiscovery(pr) {
		// The gateway's own instance for shared lists is for no
		// principal: what principals need is checked for each of them.
		return nil
	}
	for _, req := range b.Requires {
		if pr.UID == nil && strings.Contains(req, "${UID}") {
			return &MissingPathError{Server: b.Name, Path: req}
		}
		path := supervisor.ExpandVars(req, pr)
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return &MissingPathError{Server: b.Name, Path: path}
		}
	}
	return nil
}

// isNotOffered: err is notOffered's (the server is not for the
// principal, not unavailable).
func isNotOffered(err error) bool {
	var home *NoHomeError
	var missing *MissingPathError
	return errors.As(err, &home) || errors.As(err, &missing)
}
