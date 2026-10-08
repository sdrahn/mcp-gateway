package landlock

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"slices"

	"golang.org/x/sys/unix"
)

// selfEnv carries what Self applied into the program it executes again.
const selfEnv = "MCP_LANDLOCK_SELF"

// Network are the trees a program that makes TLS connections reads
// beyond Base: the CA certificates (/etc/ssl/ca-bundle.pem and
// /etc/ssl/certs lead to /var/lib/ca-certificates on SUSE) and the
// resolver configuration where netconfig keeps it (/etc/resolv.conf
// links there). Not systemd-resolved's below /run/systemd, which the
// programs' SELinux domains do not search (under the gateway they
// resolve no names: it passes the addresses).
var Network = []string{"/var/lib/ca-certificates", "/run/netconfig"}

// Self restricts the running program, and what it starts, to Base and r,
// for good. The kernel restricts the calling thread only, and a Go
// program runs on several: Self restricts a thread locked to it and
// executes the program again from that thread, with the same arguments
// and environment, so that every thread of the new program shares the
// one restriction. In the program executed again, Self returns at once
// what the first one applied (and removes its mark from the
// environment, so that the programs it starts restrict themselves
// anew). Without Landlock, Self returns without executing anything,
// unless r.Required.
//
// Call Self before the program writes anything or reads its input:
// whatever it did before, it does again. If Self fails after restricting
// (the program cannot be executed again), the thread stays restricted
// and locked, and the program should end.
func Self(r Rules) (Result, error) {
	if v, ok := os.LookupEnv(selfEnv); ok {
		_ = os.Unsetenv(selfEnv)
		var res Result
		if err := json.Unmarshal([]byte(v), &res); err != nil {
			return res, fmt.Errorf("landlock: %s: %v", selfEnv, err)
		}
		return res, nil
	}
	if ABI() == 0 {
		if r.Required {
			return Result{}, ErrRequired
		}
		return Result{}, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return Result{}, fmt.Errorf("landlock: %w", err)
	}
	// The program itself, wherever it lies (a test binary below /tmp).
	r.Exec = append(slices.Clone(r.Exec), exe)
	runtime.LockOSThread()
	res, err := Restrict(r)
	if err != nil {
		// Restrict fails before restricting anything.
		runtime.UnlockOSThread()
		return res, err
	}
	mark, _ := json.Marshal(res)
	env := append(os.Environ(), selfEnv+"="+string(mark))
	err = unix.Exec(exe, os.Args, env)
	return res, fmt.Errorf("landlock: executing %s again: %w", exe, err)
}
