package main

import (
	"errors"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/landlock"
)

// systemRead are the trees every command may read beyond landlock.Base
// (the system's configuration and programs, /proc, /sys): the system's
// state, as the shipped definition of the server allows.
var systemRead = []string{"/var", "/run"}

// landlockRules are the trees the server and its commands keep to
// (Landlock, docs/architecture.md D19): the system read (systemRead and
// landlock.Base), each command's program executed, the paths a command
// names (its dir, and the absolute paths in its argv: a whole element,
// the value of an option such as --file=/path, or the directory before
// a placeholder, /var/log for /var/log/{unit}) written, or only read
// for commands marked read_only, and what a command file's landlock
// adds for its commands. TCP is left to the server's definition and
// unit.
func landlockRules(cmds map[string]*Command) landlock.Rules {
	read, write, exec := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range systemRead {
		read[p] = true
	}
	for _, c := range cmds {
		exec[c.Argv[0]] = true
		named := read
		if !c.ReadOnly {
			named = write
		}
		if c.Dir != "" {
			named[filepath.Clean(c.Dir)] = true
		}
		for _, a := range c.Argv[1:] {
			if p := namedPath(a); p != "" {
				named[p] = true
			}
		}
		if l := c.landlock; l != nil {
			for _, p := range l.Read {
				read[p] = true
			}
			for _, p := range l.Write {
				write[p] = true
			}
			for _, p := range l.Exec {
				exec[p] = true
			}
		}
	}
	return landlock.Rules{Read: sorted(read), Write: sorted(write), Exec: sorted(exec)}
}

// namedPath is the absolute path an argv element names, or "".
func namedPath(a string) string {
	if strings.HasPrefix(a, "-") {
		_, v, ok := strings.Cut(a, "=")
		if !ok {
			return ""
		}
		a = v
	}
	if i := placeholder.FindStringIndex(a); i != nil {
		a = filepath.Dir(a[:i[0]] + "x")
	}
	if !filepath.IsAbs(a) {
		return ""
	}
	return filepath.Clean(a)
}

// validLandlock checks a command file's landlock: trees only (TCP ports
// and required belong in the server's definition), absolute and clean,
// nothing expanded.
func validLandlock(l landlock.Rules) error {
	if l.TCPConnect != nil || l.TCPBind != nil || l.Required {
		return errors.New("tcp_connect, tcp_bind and required belong in the server's definition (servers.d), not in a command file")
	}
	for _, ps := range [][]string{l.Read, l.Write, l.Exec} {
		for _, p := range ps {
			if strings.Contains(p, "$") {
				return errors.New(p + ": nothing is expanded in a command file")
			}
		}
	}
	return l.Validate()
}

func sorted(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
