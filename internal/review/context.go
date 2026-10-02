package review

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// Context is what the system says about a finding: the file a program
// resolves to or a path names, and its SELinux label.
type Context struct {
	Path    string `json:"path,omitempty"`    // the file it resolves to (for a path: itself or its nearest existing parent)
	Parent  bool   `json:"parent,omitempty"`  // the path does not exist; Path is its nearest existing parent
	Label   string `json:"label,omitempty"`   // SELinux context
	Type    string `json:"type,omitempty"`    // SELinux type
	Missing bool   `json:"missing,omitempty"` // a program not found on this system
}

// searchPath is where programs are looked for: a root's PATH.
const searchPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// Locate fills in the context of programs and paths on this system.
func Locate(f Finding) Context {
	switch f.Kind {
	case KindProgram:
		p := f.Value
		if !filepath.IsAbs(p) {
			found := ""
			for _, dir := range filepath.SplitList(searchPath) {
				if c := filepath.Join(dir, p); isExecutable(c) {
					found = c
					break
				}
			}
			if found == "" {
				if lp, err := exec.LookPath(p); err == nil {
					found = lp
				}
			}
			p = found
		}
		if p == "" || !isExecutable(p) {
			return Context{Missing: true}
		}
		return labelled(Context{Path: p})
	case KindPath:
		if strings.ContainsAny(f.Value, "%{}$") { // a format, not a path
			return Context{}
		}
		c := Context{Path: f.Value}
		for {
			if _, err := os.Lstat(c.Path); err == nil {
				break
			}
			parent := filepath.Dir(c.Path)
			if parent == c.Path {
				return Context{}
			}
			c.Path, c.Parent = parent, true
		}
		return labelled(c)
	}
	return Context{}
}

func isExecutable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0
}

// labelled adds the SELinux label of c.Path.
func labelled(c Context) Context {
	buf := make([]byte, 256)
	n, err := syscall.Getxattr(c.Path, "security.selinux", buf)
	if err != nil || n == 0 {
		return c
	}
	c.Label = strings.TrimRight(string(buf[:n]), "\x00")
	if parts := strings.SplitN(c.Label, ":", 4); len(parts) >= 3 {
		c.Type = parts[2]
	}
	return c
}
