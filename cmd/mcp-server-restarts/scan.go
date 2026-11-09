package main

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Report is what an update left waiting.
type Report struct {
	// RebootNeeded: the flag zypper and transactional-update leave after
	// an update that needs a reboot (RebootFlag) exists; RebootNeededSince
	// is its modification time.
	RebootNeeded      bool   `json:"reboot_needed"`
	RebootNeededSince string `json:"reboot_needed_since,omitempty"`
	// RunningKernel is the running kernel's release (uname -r);
	// InstalledKernels those with a kernel image below ModulesDir, oldest
	// first; NewerKernel: the newest installed is not the running one.
	RunningKernel    string   `json:"running_kernel"`
	InstalledKernels []string `json:"installed_kernels"`
	NewerKernel      bool     `json:"newer_kernel_installed"`
	// Services are the systemd services with a process in Processes.
	Services  []Service `json:"services"`
	Processes []Process `json:"processes"`
	// Unreadable counts the processes whose memory maps could not be
	// read (they ended, or the server lacks the right).
	Unreadable int `json:"unreadable,omitempty"`
}

// Service is a systemd unit whose processes use files an update replaced
// or removed.
type Service struct {
	Unit     string   `json:"unit"`
	PIDs     []int    `json:"pids"`
	Packages []string `json:"packages"`
}

// Process uses files an update replaced or removed (deleted while
// mapped): as zypper ps -s lists them.
type Process struct {
	PID     int    `json:"pid"`
	Command string `json:"command"`
	User    string `json:"user"`
	// Unit is the systemd unit of its control group (a .service, a
	// session's .scope), if any.
	Unit string `json:"unit,omitempty"`
	// Files are the deleted files it maps; Packages those that own a
	// file at the same path now (the update that replaced it).
	Files    []string `json:"files"`
	Packages []string `json:"packages"`
}

// scanner reads the system; its paths are fields for the tests.
type scanner struct {
	proc       string // /proc
	modules    string // /usr/lib/modules
	rebootFlag string // /run/reboot-needed
	self       int    // the server's own pid, left out
	release    func() string
	// owner returns the package owning path, "" for none.
	owner func(ctx context.Context, path string) string
	user  func(uid string) string
}

// Paths the scanner reads on the host.
const (
	procDir    = "/proc"
	modulesDir = "/usr/lib/modules"
	RebootFlag = "/run/reboot-needed"
	rpmProgram = "/usr/bin/rpm"
)

func newScanner() *scanner {
	return &scanner{proc: procDir, modules: modulesDir, rebootFlag: RebootFlag, self: os.Getpid(),
		release: kernelRelease, owner: rpmOwner, user: userName}
}

// maxFiles bounds the deleted files looked up in the rpm database per
// call (each is one rpm -qf).
const maxFiles = 256

func (s *scanner) scan(ctx context.Context) Report {
	var r Report
	if fi, err := os.Stat(s.rebootFlag); err == nil {
		r.RebootNeeded = true
		r.RebootNeededSince = fi.ModTime().UTC().Format(time.RFC3339)
	}
	r.RunningKernel = s.release()
	r.InstalledKernels = s.kernels()
	if n := len(r.InstalledKernels); n > 0 && r.InstalledKernels[n-1] != r.RunningKernel {
		r.NewerKernel = r.RunningKernel == "" || vercmp(r.InstalledKernels[n-1], r.RunningKernel) > 0
	}

	entries, _ := os.ReadDir(s.proc)
	owners := map[string]string{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == s.self {
			continue
		}
		dir := filepath.Join(s.proc, e.Name())
		files, ok := deletedFiles(filepath.Join(dir, "maps"))
		if !ok {
			// A kernel thread has an empty map; a process that ended or
			// whose map is refused has none.
			if _, err := os.Stat(dir); err == nil && !kernelThread(dir) {
				r.Unreadable++
			}
			continue
		}
		if len(files) == 0 {
			continue
		}
		p := Process{PID: pid, Command: readLine(filepath.Join(dir, "comm")), User: s.user(uidOf(dir)),
			Unit: unitOf(filepath.Join(dir, "cgroup")), Files: files, Packages: []string{}}
		for _, f := range files {
			name, seen := owners[f]
			if !seen && len(owners) < maxFiles {
				name = s.owner(ctx, f)
				owners[f] = name
			}
			if name != "" && !slices.Contains(p.Packages, name) {
				p.Packages = append(p.Packages, name)
			}
		}
		slices.Sort(p.Packages)
		r.Processes = append(r.Processes, p)
	}
	slices.SortFunc(r.Processes, func(a, b Process) int { return a.PID - b.PID })
	r.Services = services(r.Processes)
	if r.Processes == nil {
		r.Processes = []Process{}
	}
	return r
}

// services groups the processes of systemd services by unit.
func services(ps []Process) []Service {
	by := map[string]*Service{}
	for _, p := range ps {
		if !strings.HasSuffix(p.Unit, ".service") {
			continue
		}
		s := by[p.Unit]
		if s == nil {
			s = &Service{Unit: p.Unit, Packages: []string{}}
			by[p.Unit] = s
		}
		s.PIDs = append(s.PIDs, p.PID)
		for _, pkg := range p.Packages {
			if !slices.Contains(s.Packages, pkg) {
				s.Packages = append(s.Packages, pkg)
			}
		}
	}
	out := []Service{}
	for _, s := range by {
		slices.Sort(s.Packages)
		out = append(out, *s)
	}
	slices.SortFunc(out, func(a, b Service) int { return strings.Compare(a.Unit, b.Unit) })
	return out
}

// systemTrees are where an update puts the files a process maps:
// programs, libraries, their data. A deleted file elsewhere (a temporary
// file, shared memory, a user's file) is no update's doing.
var systemTrees = []string{"/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/opt/", "/etc/"}

// deletedFiles are the files of system trees a process maps that were
// deleted (replaced by an update, or removed), from its maps; ok is
// false when they cannot be read.
func deletedFiles(maps string) (files []string, ok bool) {
	f, err := os.Open(maps)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	files = []string{}
	for sc.Scan() {
		line := sc.Text()
		// address perms offset dev inode pathname
		fields := strings.SplitN(line, " ", 6)
		if len(fields) < 6 {
			continue
		}
		path := strings.TrimLeft(fields[5], " ")
		path, deleted := strings.CutSuffix(path, " (deleted)")
		if !deleted || !inSystemTree(path) || slices.Contains(files, path) {
			continue
		}
		files = append(files, path)
	}
	if sc.Err() != nil {
		return nil, false
	}
	return files, true
}

func inSystemTree(path string) bool {
	for _, t := range systemTrees {
		if strings.HasPrefix(path, t) {
			return true
		}
	}
	return false
}

// kernelThread: a process without a user space (kernel threads have no
// command line).
func kernelThread(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "cmdline"))
	return err == nil && len(b) == 0
}

func readLine(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(line)
}

// uidOf is a process's real user id, from its status.
func uidOf(dir string) string {
	f, err := os.Open(filepath.Join(dir, "status"))
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "Uid:"); ok {
			if fields := strings.Fields(rest); len(fields) > 0 {
				return fields[0]
			}
		}
	}
	return ""
}

// unitOf is the systemd unit of a process's control group (cgroup v2:
// "0::/system.slice/sshd.service"), "" for none.
func unitOf(cgroup string) string {
	b, err := os.ReadFile(cgroup)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		path, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		parts := strings.Split(strings.Trim(path, "/"), "/")
		// The innermost unit: a service's own sub-groups come after it.
		for i := len(parts) - 1; i >= 0; i-- {
			if strings.HasSuffix(parts[i], ".service") || strings.HasSuffix(parts[i], ".scope") {
				return parts[i]
			}
		}
	}
	return ""
}

// kernels are the releases below modules with a kernel image, oldest
// first.
func (s *scanner) kernels() []string {
	entries, _ := os.ReadDir(s.modules)
	out := []string{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		for _, img := range []string{"vmlinuz", "Image", "vmlinux.gz", "vmlinux"} {
			if _, err := os.Stat(filepath.Join(s.modules, e.Name(), img)); err == nil {
				out = append(out, e.Name())
				break
			}
		}
	}
	slices.SortFunc(out, vercmp)
	return out
}

// vercmp compares versions as rpm does, roughly: digits as numbers,
// letters as text, separators only separate.
func vercmp(a, b string) int {
	split := func(s string) []string {
		var out []string
		cur := ""
		kind := 0 // 1 digit, 2 letter
		for _, r := range s {
			k := 0
			switch {
			case unicode.IsDigit(r):
				k = 1
			case unicode.IsLetter(r):
				k = 2
			}
			if k != kind && cur != "" {
				out = append(out, cur)
				cur = ""
			}
			kind = k
			if k != 0 {
				cur += string(r)
			}
		}
		if cur != "" {
			out = append(out, cur)
		}
		return out
	}
	as, bs := split(a), split(b)
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, y := as[i], bs[i]
		xn, xerr := strconv.ParseUint(x, 10, 64)
		yn, yerr := strconv.ParseUint(y, 10, 64)
		switch {
		case xerr == nil && yerr == nil:
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
		case xerr == nil:
			return 1 // a number is newer than letters
		case yerr == nil:
			return -1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return len(as) - len(bs)
}

// rpmOwner is the package that owns path now, from the rpm database.
func rpmOwner(ctx context.Context, path string) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, rpmProgram, "-qf", "--qf", "%{NAME}\n", "--", path).Output()
	if err != nil {
		// Owned by none, or the file is gone for good.
		return ""
	}
	name := strings.TrimSpace(string(out))
	if strings.ContainsAny(name, " \n") {
		return ""
	}
	return name
}

func userName(uid string) string {
	if uid == "" {
		return ""
	}
	if u, err := user.LookupId(uid); err == nil {
		return u.Username
	}
	return uid
}
