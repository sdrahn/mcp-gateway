package authn

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// LoginDefs are the files the range of people's accounts is read from,
// the first that exists winning (/usr/etc for distributions that ship
// their defaults there).
var LoginDefs = []string{"/etc/login.defs", "/usr/etc/login.defs"}

// The range of people's accounts when login.defs does not say
// (shadow-utils' defaults).
const (
	defaultUIDMin = 1000
	defaultUIDMax = 60000
)

// peopleUIDs returns UID_MIN and UID_MAX of login.defs: the accounts a
// token may map to (never root, a system account, or nobody).
var peopleUIDs = func() (uint32, uint32) { return loginDefsRange(LoginDefs) }

func loginDefsRange(paths []string) (uint32, uint32) {
	lo, hi := uint32(defaultUIDMin), uint32(defaultUIDMax)
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 {
				continue
			}
			n, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				continue
			}
			switch fields[0] {
			case "UID_MIN":
				lo = uint32(n)
			case "UID_MAX":
				hi = uint32(n)
			}
		}
		_ = f.Close()
		break
	}
	if lo == 0 {
		lo = 1
	}
	return lo, hi
}
