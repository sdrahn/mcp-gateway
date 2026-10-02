package supervisor

import (
	"errors"
	"os"
	"sort"
	"syscall"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// selinuxContextFile is selinuxfs's context file: writing a context to
// it asks the kernel whether the loaded policy knows it
// (security_check_context).
const selinuxContextFile = "/sys/fs/selinux/context"

// ContextValid reports whether ctx is a valid context in the loaded
// policy. The error is non-nil if that could not be asked (no selinuxfs,
// or the caller may not check contexts).
func ContextValid(ctx string) (bool, error) {
	f, err := os.OpenFile(selinuxContextFile, os.O_RDWR, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write([]byte(ctx)); err != nil {
		if errors.Is(err, syscall.EINVAL) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// MissingSELinuxTypes returns, per selinux_type that valid does not
// accept, the servers that name it. An instance of such a server cannot
// start: systemd fails to set its context ("Failed to change SELinux
// context"), even in permissive mode. The usual cause is a server
// definition installed without its SELinux module. valid is ContextValid
// outside tests.
func MissingSELinuxTypes(backends map[string]*config.Backend, valid func(ctx string) (bool, error)) (map[string][]string, error) {
	servers := map[string][]string{}
	for name, b := range backends {
		servers[b.SELinuxType] = append(servers[b.SELinuxType], name)
	}
	missing := map[string][]string{}
	for t, names := range servers {
		ok, err := valid("system_u:system_r:" + t + ":s0")
		if err != nil {
			return nil, err
		}
		if !ok {
			sort.Strings(names)
			missing[t] = names
		}
	}
	return missing, nil
}
