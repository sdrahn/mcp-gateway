// Package statedir knows who owns the gateway's state: the account the
// service runs as, and the files in its directories that others own.
package statedir

import (
	"errors"
	"io/fs"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// User is the account mcp-gateway.service runs as.
const User = "mcp-gateway"

// ForeignFile is a file in a gateway directory that another user owns.
type ForeignFile struct {
	Path string
	UID  uint32
}

func (f ForeignFile) String() string {
	owner := strconv.FormatUint(uint64(f.UID), 10)
	if u, err := user.LookupId(owner); err == nil {
		owner = u.Username
	}
	return f.Path + " (owner " + owner + ")"
}

// ForeignFiles returns the files below dir, dir included, that uid does
// not own. A missing dir has none.
func ForeignFiles(dir string, uid uint32) ([]ForeignFile, error) {
	var out []ForeignFile
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == dir && errors.Is(err, fs.ErrNotExist) {
				return filepath.SkipDir
			}
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != uid {
			out = append(out, ForeignFile{path, st.Uid})
		}
		return nil
	})
	return out, err
}
