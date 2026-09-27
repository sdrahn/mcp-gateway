package authn

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/user"
	"strconv"

	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

// Local builds the principal for a local client from its kernel-provided
// peer credentials. User and group names are resolved through NSS when the
// binary is built with cgo (SSSD/IPA), otherwise from /etc/passwd and
// /etc/group.
func Local(peer transport.PeerCred) (principal.Principal, error) {
	uid := peer.UID
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return principal.Principal{}, fmt.Errorf("authn: unknown uid %d: %w", uid, err)
	}
	gids, err := u.GroupIds()
	if err != nil {
		return principal.Principal{}, fmt.Errorf("authn: groups of %s: %w", u.Username, err)
	}
	groups := make([]string, 0, len(gids))
	for _, gid := range gids {
		if g, err := user.LookupGroupId(gid); err == nil {
			groups = append(groups, g.Name)
		}
	}
	return principal.Principal{
		Sub:       u.Username,
		UID:       &uid,
		Groups:    groups,
		Home:      u.HomeDir,
		Transport: principal.TransportUnix,
		SELinux:   peer.Label,
		SessionID: NewSessionID(),
	}, nil
}

// NewSessionID returns a random 16-hex-digit session id. It is also used in
// unit names, so it only contains [0-9a-f].
func NewSessionID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
