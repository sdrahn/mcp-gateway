package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// allowed is one directory the tools work in. Every file operation goes
// through its os.Root, so a symbolic link inside it that points out of it
// is refused by the kernel, not only by a check of the path as a string
// (docs/architecture.md, decision D13).
type allowed struct {
	path string // absolute, cleaned

	once sync.Once
	root *os.Root
	err  error
}

// open opens the directory on first use, not at start: a discovery
// instance, which only lists tools, may run with a root it cannot read.
func (a *allowed) open() (*os.Root, error) {
	a.once.Do(func() { a.root, a.err = os.OpenRoot(a.path) })
	return a.root, a.err
}

// target is a path argument resolved to an allowed directory and a name
// relative to it ("." for the directory itself).
type target struct {
	dir  *allowed
	rel  string
	full string // absolute, for messages
}

func (t target) isRoot() bool { return t.rel == "." }

// resolve maps a path argument to an allowed directory: an absolute path
// (or ~/...) must lie below one of them (the longest that matches); a
// relative path is relative to the first.
func (s *fileServer) resolve(p string) (target, error) {
	if p == "" {
		return target{}, errors.New("path is required")
	}
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(s.dirs[0].path, p)
	}
	p = filepath.Clean(p)
	var best *allowed
	for _, a := range s.dirs {
		if (p == a.path || strings.HasPrefix(p, a.path+"/") || a.path == "/") && (best == nil || len(a.path) > len(best.path)) {
			best = a
		}
	}
	if best == nil {
		return target{}, fmt.Errorf("%s: outside the allowed directories (%s)", p, strings.Join(s.dirPaths(), ", "))
	}
	rel, err := filepath.Rel(best.path, p)
	if err != nil {
		return target{}, err
	}
	return target{dir: best, rel: rel, full: p}, nil
}

func (s *fileServer) dirPaths() []string {
	out := make([]string, len(s.dirs))
	for i, a := range s.dirs {
		out[i] = a.path
	}
	return out
}

// explain turns an error from a file operation into a message that names
// the path the agent gave and says what went wrong.
func explain(t target, err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	var le *os.LinkError
	if errors.As(err, &le) {
		err = le.Err
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%s: no such file or directory", t.full)
	case errors.Is(err, syscall.ENOTEMPTY): // before ErrExist, which matches it too
		return fmt.Errorf("%s: directory not empty", t.full)
	case errors.Is(err, fs.ErrExist):
		return fmt.Errorf("%s: already exists", t.full)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%s: permission denied", t.full)
	case strings.Contains(err.Error(), "escapes from parent"), strings.Contains(err.Error(), "path escapes"):
		return fmt.Errorf("%s: leads outside the allowed directories (through a symbolic link)", t.full)
	case errors.Is(err, syscall.ENOTDIR):
		return fmt.Errorf("%s: a component is not a directory", t.full)
	case errors.Is(err, syscall.EISDIR):
		return fmt.Errorf("%s: is a directory", t.full)
	case errors.Is(err, syscall.EROFS):
		return fmt.Errorf("%s: read-only file system", t.full)
	case errors.Is(err, syscall.ENOSPC):
		return fmt.Errorf("%s: no space left on device", t.full)
	}
	return fmt.Errorf("%s: %v", t.full, err)
}

// parent opens the directory that contains t, through the root, and
// returns it with t's base name. Operations on the base name relative to
// that directory (renameat) cannot leave the root: the directory was
// opened through it, and the base name has no slash.
func parent(t target) (*os.File, string, error) {
	if t.isRoot() {
		return nil, "", fmt.Errorf("%s: not allowed on an allowed directory itself", t.full)
	}
	root, err := t.dir.open()
	if err != nil {
		return nil, "", err
	}
	d, err := root.Open(filepath.Dir(t.rel))
	if err != nil {
		return nil, "", err
	}
	return d, filepath.Base(t.rel), nil
}

// mkdirAll creates t and its missing parents, one component at a time
// through the root.
func mkdirAll(t target) error {
	root, err := t.dir.open()
	if err != nil {
		return err
	}
	if t.isRoot() {
		return nil
	}
	cur := ""
	for _, part := range strings.Split(t.rel, "/") {
		cur = filepath.Join(cur, part)
		err := root.Mkdir(cur, 0o755)
		if err == nil {
			continue
		}
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
		fi, err := root.Stat(cur)
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s: %w", cur, syscall.ENOTDIR)
		}
	}
	return nil
}

// writeAtomic replaces (or creates) t with data: a temporary file next to
// it, synced, then renamed over it. A failure leaves the old file as it
// was. An existing file keeps its permissions; t must not be a symbolic
// link (renaming over it would replace the link, not its target).
func writeAtomic(t target, data []byte) error {
	root, err := t.dir.open()
	if err != nil {
		return err
	}
	mode := fs.FileMode(0o644)
	if fi, err := root.Lstat(t.rel); err == nil {
		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			return errors.New("is a symbolic link: write to the file it points to")
		case fi.IsDir():
			return syscall.EISDIR
		}
		mode = fi.Mode().Perm()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	dir, base, err := parent(t)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	tmp := filepath.Join(filepath.Dir(t.rel), "."+base+".tmp-"+randomSuffix())
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(int(dir.Fd()), filepath.Base(tmp), int(dir.Fd()), base)
	}
	if err != nil {
		_ = root.Remove(tmp)
		return err
	}
	return nil
}

// move renames src to dst within one allowed directory, refusing to
// replace an existing dst.
func move(src, dst target) error {
	if src.dir != dst.dir {
		return fmt.Errorf("%s and %s are in different allowed directories: copy and delete instead", src.full, dst.full)
	}
	sd, sbase, err := parent(src)
	if err != nil {
		return explain(src, err)
	}
	defer func() { _ = sd.Close() }()
	dd, dbase, err := parent(dst)
	if err != nil {
		return explain(dst, err)
	}
	defer func() { _ = dd.Close() }()
	err = unix.Renameat2(int(sd.Fd()), sbase, int(dd.Fd()), dbase, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) {
		// No RENAME_NOREPLACE on this file system: check, then rename.
		if serr := unix.Fstatat(int(dd.Fd()), dbase, new(unix.Stat_t), unix.AT_SYMLINK_NOFOLLOW); serr == nil {
			return explain(dst, fs.ErrExist)
		}
		err = unix.Renameat(int(sd.Fd()), sbase, int(dd.Fd()), dbase)
	}
	switch {
	case errors.Is(err, unix.EEXIST):
		return explain(dst, fs.ErrExist)
	case errors.Is(err, unix.ENOENT):
		return explain(src, fs.ErrNotExist)
	case err != nil:
		return explain(src, err)
	}
	return nil
}

// readLimited reads all of r, failing beyond max bytes.
func readLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errTooLarge
	}
	return b, nil
}

var errTooLarge = errors.New("too large")

func randomSuffix() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
