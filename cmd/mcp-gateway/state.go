package main

import (
	"fmt"
	"os/user"
	"strconv"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/statedir"
)

// gatewayUser is the account mcp-gateway.service runs as.
const gatewayUser = statedir.User

// refuseRoot returns an error if the gateway is about to run as root on a
// system that has its service account: as root it would create state
// files (pending.json, grants.json) that the service cannot read, and the
// service would then fail at start. lookup is user.Lookup outside tests.
func refuseRoot(euid int, allowRoot bool, lookup func(string) (*user.User, error)) error {
	if euid != 0 || allowRoot {
		return nil
	}
	if _, err := lookup(gatewayUser); err != nil {
		return nil
	}
	return fmt.Errorf("refusing to run as root: files the gateway creates would be root's, and %s.service, "+
		"which runs as %s, would fail to start; run it as that user "+
		"(systemctl stop %[1]s; runuser -u %[2]s -- mcp-gateway), or pass -allow-root", gatewayUser, gatewayUser)
}

// checkStateOwnership returns an error naming the files in the state
// directory that the gateway's user (uid, its effective user) does not
// own; reading or replacing them would fail later with a bare permission
// error. Root, which may run the gateway with -allow-root, reads them all.
func checkStateOwnership(dir string, uid int) error {
	if uid == 0 {
		return nil
	}
	foreign, err := statedir.ForeignFiles(dir, uint32(uid))
	if err != nil {
		return fmt.Errorf("state directory: %w", err)
	}
	if len(foreign) == 0 {
		return nil
	}
	names := make([]string, len(foreign))
	for i, f := range foreign {
		names[i] = f.String()
	}
	me := strconv.Itoa(uid)
	if u, err := user.LookupId(me); err == nil {
		me = u.Username
	}
	return fmt.Errorf("state files not owned by %s, the gateway's user (was the gateway run as root?): %s; "+
		"fix with: chown -R %s: %s", me, strings.Join(names, ", "), me, dir)
}
