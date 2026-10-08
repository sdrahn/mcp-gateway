package profile

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/landlock"
)

// Landlock leaves no audit record of what it refuses, and a server's
// SELinux denials name only what its domain lacks. To draft a landlock
// for a server, the profiling run samples what the instance's processes
// have open: their file descriptors (with the mode they were opened
// in), working directories and mapped files (programs and libraries).
// Short opens between two samples go unseen: the draft says so.

// Use is how a path was used: read, written, executed (bits).
type Use int

const (
	UseRead Use = 1 << iota
	UseWrite
	UseExec
)

// Sampler collects the paths the processes of an instance use.
type Sampler struct {
	mu   sync.Mutex
	seen map[string]Use
	// Samples counts the samples taken.
	Samples int
}

// NewSampler returns an empty sampler.
func NewSampler() *Sampler { return &Sampler{seen: map[string]Use{}} }

// Seen returns the paths used so far.
func (s *Sampler) Seen() map[string]Use {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]Use, len(s.seen))
	for p, u := range s.seen {
		out[p] = u
	}
	return out
}

func (s *Sampler) add(p string, u Use) {
	p = strings.TrimSuffix(p, " (deleted)")
	if !strings.HasPrefix(p, "/") {
		return // pipe:[…], socket:[…], anon_inode:…
	}
	s.mu.Lock()
	s.seen[filepath.Clean(p)] |= u
	s.mu.Unlock()
}

// Sample records what the processes pids have open, read below proc
// (/proc).
func (s *Sampler) Sample(proc string, pids []int) {
	for _, pid := range pids {
		dir := filepath.Join(proc, strconv.Itoa(pid))
		if cwd, err := os.Readlink(filepath.Join(dir, "cwd")); err == nil {
			s.add(cwd, UseRead)
		}
		fds, _ := os.ReadDir(filepath.Join(dir, "fd"))
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			if err != nil {
				continue
			}
			s.add(target, fdUse(filepath.Join(dir, "fdinfo", fd.Name())))
		}
		if f, err := os.Open(filepath.Join(dir, "maps")); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				// address perms offset dev inode path
				fields := strings.Fields(sc.Text())
				if len(fields) < 6 {
					continue
				}
				u := UseRead
				if strings.Contains(fields[1], "x") {
					u = UseExec
				}
				s.add(strings.Join(fields[5:], " "), u)
			}
			_ = f.Close()
		}
	}
	s.mu.Lock()
	s.Samples++
	s.mu.Unlock()
}

// fdUse reads the access mode from an fdinfo file (flags, octal).
func fdUse(fdinfo string) Use {
	data, err := os.ReadFile(fdinfo)
	if err != nil {
		return UseRead
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "flags:"); ok {
			flags, err := strconv.ParseInt(strings.TrimSpace(v), 8, 64)
			if err == nil && flags&3 != 0 { // O_WRONLY, O_RDWR
				return UseWrite
			}
		}
	}
	return UseRead
}

// Run samples the processes of the unit's control group every interval
// until ctx ends, and once more then.
func (s *Sampler) Run(ctx context.Context, unit string, every time.Duration) {
	cg := controlGroup(unit)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if cg == "" {
			cg = controlGroup(unit)
		}
		if cg != "" {
			s.Sample("/proc", cgroupPids(cg))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// controlGroup is the cgroup directory of a unit, "" if unknown yet.
func controlGroup(unit string) string {
	out, err := exec.Command("systemctl", "show", "-p", "ControlGroup", "--value", unit).Output()
	cg := strings.TrimSpace(string(out))
	if err != nil || cg == "" {
		return ""
	}
	return filepath.Join("/sys/fs/cgroup", cg)
}

// cgroupPids are the processes of a cgroup and its children.
func cgroupPids(dir string) []int {
	var pids []int
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "cgroup.procs" {
			return nil
		}
		data, _ := os.ReadFile(p)
		for _, f := range strings.Fields(string(data)) {
			if n, err := strconv.Atoi(f); err == nil {
				pids = append(pids, n)
			}
		}
		return nil
	})
	return pids
}

// DenialUses are the absolute paths of SELinux denials, by how they were
// used (name= alone, a last component, says too little).
func DenialUses(ds []Denial) map[string]Use {
	out := map[string]Use{}
	for _, d := range ds {
		if !strings.HasPrefix(d.Path, "/") {
			continue
		}
		u := UseRead
		for _, p := range d.Perms {
			switch p {
			case "write", "append", "create", "unlink", "rename", "add_name", "remove_name", "setattr", "link":
				u |= UseWrite
			case "execute", "execute_no_trans", "entrypoint":
				u |= UseExec
			}
		}
		out[filepath.Clean(d.Path)] |= u
	}
	return out
}

// pseudo are trees whose paths say nothing a ruleset needs: they are the
// base's, or not files (pts, memfd).
var pseudo = []string{"/proc", "/sys", "/dev/pts", "/memfd:", "/run/credentials"}

// DraftLandlock reduces the paths a run used to the trees of a landlock
// beyond landlock.Base: a file stands for its directory, a directory for
// itself (not /, which restricts nothing); trees inside another with the
// same use are dropped. Writes below a tree the base only reads (/etc)
// are kept. isDir tells directories (os.Stat, for tests a stub).
func DraftLandlock(used map[string]Use, isDir func(string) bool) landlock.Rules {
	trees := map[string]Use{}
	for p, u := range used {
		if under(p, pseudo) {
			continue
		}
		if u&UseExec != 0 && under(p, landlock.Base.Exec) {
			u &^= UseExec
		}
		if u&UseWrite != 0 && under(p, landlock.Base.Write) {
			u &^= UseWrite
		}
		if u&UseWrite == 0 && u&UseExec == 0 && under(p, slicesOf(landlock.Base.Read, landlock.Base.Exec, landlock.Base.Write)) {
			continue
		}
		if u == 0 {
			continue
		}
		t := p
		if !isDir(p) {
			t = filepath.Dir(p)
		}
		if t == "/" {
			// The root itself (an instance's working directory, as a
			// rule): a tree of / restricts nothing.
			continue
		}
		trees[t] |= u | UseRead // writing and executing read too
	}
	var r landlock.Rules
	for _, t := range sortedTrees(trees) {
		u := trees[t]
		covered := false
		for _, o := range sortedTrees(trees) {
			if o != t && within(t, o) && trees[o]&u == u {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		// Written trees are not executed (landlock's write leaves out
		// EXECUTE): a tree both written and executed is in both.
		if u&UseWrite != 0 {
			r.Write = append(r.Write, t)
		}
		if u&UseExec != 0 {
			r.Exec = append(r.Exec, t)
		}
		if u&(UseWrite|UseExec) == 0 {
			r.Read = append(r.Read, t)
		}
	}
	return r
}

func slicesOf(ls ...[]string) []string {
	var out []string
	for _, l := range ls {
		out = append(out, l...)
	}
	return out
}

func sortedTrees(m map[string]Use) []string {
	out := make([]string, 0, len(m))
	for t := range m {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// within reports whether p is t or below it.
func within(p, t string) bool {
	return p == t || t == "/" || strings.HasPrefix(p, t+"/")
}

// under reports whether p lies within one of trees (or is a pseudo
// prefix like /memfd:).
func under(p string, trees []string) bool {
	for _, t := range trees {
		if within(p, t) || (strings.HasSuffix(t, ":") && strings.HasPrefix(p, t)) {
			return true
		}
	}
	return false
}
