// Package review scans an MCP server's source for what it does to the
// system: programs it runs, D-Bus services and polkit actions it names,
// paths, network access, root checks and environment variables. It backs
// "mcp-gateway-admin review", which helps a reviewer find what a profiling run
// (internal/profile) did not reach. The scan is textual: it finds the
// usual ways of doing these things in Go, Python, JavaScript/TypeScript,
// C/C++ and Rust, not every way.
//
// See docs/architecture.md, section 11, step 11.
package review

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Kind is what a finding is about.
type Kind string

const (
	KindProgram Kind = "program" // a program it runs
	KindDBus    Kind = "dbus"    // a D-Bus name, interface or polkit action
	KindPath    Kind = "path"    // an absolute path
	KindNetwork Kind = "network" // network access or a URL
	KindRoot    Kind = "root"    // a check for root
	KindEnv     Kind = "env"     // an environment variable it reads
)

// Kinds lists the kinds in report order.
var Kinds = []Kind{KindProgram, KindDBus, KindPath, KindNetwork, KindRoot, KindEnv}

// Location is where a finding is in the source.
type Location struct {
	File string `json:"file"` // relative to the scanned directory
	Line int    `json:"line"`
	Text string `json:"text"` // the line, trimmed
}

// Finding is one thing the source does, with every place it does it.
type Finding struct {
	Kind      Kind       `json:"kind"`
	Value     string     `json:"value"` // program, name, path, host, variable
	Locations []Location `json:"locations"`
}

// Scan is the result of scanning a source tree.
type Scan struct {
	Files    map[string]int `json:"files"` // by language
	Findings []Finding      `json:"findings"`
}

type rule struct {
	kind  Kind
	re    *regexp.Regexp
	value func(m []string) string // from the submatches; nil: the first group, else the whole match
}

func group(i int) func([]string) string { return func(m []string) string { return m[i] } }

func constant(s string) func([]string) string { return func([]string) string { return s } }

var (
	// Programs: the first argument of the common ways to run one.
	progGo     = regexp.MustCompile(`exec\.Command(?:Context)?\(\s*(?:[A-Za-z_][A-Za-z0-9_.]*,\s*)?"([^"]+)"`)
	progPy     = regexp.MustCompile(`(?:subprocess\.(?:run|Popen|call|check_call|check_output)|asyncio\.create_subprocess_exec)\(\s*\[?\s*["']([^"']+)["']`)
	progPySh   = regexp.MustCompile(`os\.(?:system|popen)\(\s*["']([^"' ]+)`)
	progJS     = regexp.MustCompile(`\b(?:spawn|spawnSync|execFile|execFileSync|exec|execSync)\(\s*["'` + "`" + `]([^"'` + "`" + ` ]+)`)
	progC      = regexp.MustCompile(`\b(?:execlp?|execvp?e?|popen|system|posix_spawnp?)\(\s*(?:[^,"]*,\s*)?"([^" ]+)`)
	progRust   = regexp.MustCompile(`Command::new\(\s*"([^"]+)"`)
	dbusName   = regexp.MustCompile(`["']((?:org|com|net|io)\.(?:freedesktop|fedoraproject|opensuse|suse|gnome|kde)\.[A-Za-z0-9_.-]+)["']`)
	absPath    = regexp.MustCompile(`["'` + "`" + `](/(?:etc|var|run|usr|proc|sys|dev|home|root|tmp|opt|srv|boot|lib|lib64)(?:/[A-Za-z0-9._@%+:-]*)*)["'` + "`" + `]`)
	url        = regexp.MustCompile(`["'` + "`" + `](https?://[^"'` + "`" + `\s/]+)`)
	netGo      = regexp.MustCompile(`\b(?:net\.Dial(?:Timeout)?|net\.Listen|http\.(?:Get|Post|Head|NewRequest(?:WithContext)?)|tls\.Dial)\(`)
	netPy      = regexp.MustCompile(`\b(?:requests\.(?:get|post|put|delete|request|Session)|urllib\.request\.urlopen|httpx\.|aiohttp\.|socket\.socket|socket\.create_connection)\b`)
	netJS      = regexp.MustCompile(`\b(?:fetch|axios(?:\.\w+)?|https?\.(?:request|get)|net\.connect|net\.createConnection)\(`)
	netC       = regexp.MustCompile(`\b(?:getaddrinfo|curl_easy_perform)\(`)
	rootGo     = regexp.MustCompile(`\bos\.Gete?uid\(\)`)
	rootPy     = regexp.MustCompile(`\bos\.gete?uid\(\)`)
	rootJS     = regexp.MustCompile(`\bprocess\.gete?uid\(\)`)
	rootC      = regexp.MustCompile(`\bgete?uid\(\)`)
	rootRust   = regexp.MustCompile(`\b(?:nix::unistd::)?gete?uid\(\)|users::get_current_uid\(\)`)
	envGo      = regexp.MustCompile(`\bos\.(?:Getenv|LookupEnv)\(\s*"([A-Za-z_][A-Za-z0-9_]*)"`)
	envPy      = regexp.MustCompile(`\bos\.(?:environ\.get|getenv)\(\s*["']([A-Za-z_][A-Za-z0-9_]*)["']|\bos\.environ\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\]`)
	envJS      = regexp.MustCompile(`\bprocess\.env\.([A-Za-z_][A-Za-z0-9_]*)|\bprocess\.env\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\]`)
	envC       = regexp.MustCompile(`\b(?:secure_)?getenv\(\s*"([A-Za-z_][A-Za-z0-9_]*)"`)
	envRust    = regexp.MustCompile(`\benv::var(?:_os)?\(\s*"([A-Za-z_][A-Za-z0-9_]*)"`)
	firstGroup = func(m []string) string {
		for _, g := range m[1:] {
			if g != "" {
				return g
			}
		}
		return ""
	}
)

// binPath matches paths of programs.
var binPath = regexp.MustCompile(`^/(?:usr/(?:local/)?)?(?:s?bin|libexec)/[^/]+$`)

// common holds the rules that apply to every language.
var common = []rule{
	{KindDBus, dbusName, group(1)},
	{KindPath, absPath, group(1)},
	{KindNetwork, url, group(1)},
}

var languages = map[string][]rule{
	"Go": {
		{KindProgram, progGo, group(1)},
		{KindNetwork, netGo, constant("network calls (Go net/http)")},
		{KindRoot, rootGo, constant("root check")},
		{KindEnv, envGo, group(1)},
	},
	"Python": {
		{KindProgram, progPy, group(1)},
		{KindProgram, progPySh, group(1)},
		{KindNetwork, netPy, constant("network calls (Python)")},
		{KindRoot, rootPy, constant("root check")},
		{KindEnv, envPy, firstGroup},
	},
	"JavaScript": {
		{KindProgram, progJS, group(1)},
		{KindNetwork, netJS, constant("network calls (JavaScript)")},
		{KindRoot, rootJS, constant("root check")},
		{KindEnv, envJS, firstGroup},
	},
	"C/C++": {
		{KindProgram, progC, group(1)},
		{KindNetwork, netC, constant("network calls (C)")},
		{KindRoot, rootC, constant("root check")},
		{KindEnv, envC, group(1)},
	},
	"Rust": {
		{KindProgram, progRust, group(1)},
		{KindRoot, rootRust, constant("root check")},
		{KindEnv, envRust, group(1)},
	},
}

var extensions = map[string]string{
	".go": "Go", ".py": "Python",
	".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript", ".ts": "JavaScript", ".mts": "JavaScript",
	".c": "C/C++", ".h": "C/C++", ".cc": "C/C++", ".cpp": "C/C++", ".cxx": "C/C++", ".hh": "C/C++", ".hpp": "C/C++",
	".rs": "Rust",
}

// skipDir names directories that are not the server's own code.
var skipDir = map[string]bool{
	".git": true, "vendor": true, "node_modules": true, "third_party": true, "testdata": true,
	"test": true, "tests": true, "__pycache__": true, ".venv": true, "venv": true, "target": true, "dist": true, "build": true,
}

// isTest reports files that are tests.
func isTest(name string) bool {
	return strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, "test_") ||
		strings.HasSuffix(name, "_test.py") || strings.Contains(name, ".test.") || strings.Contains(name, ".spec.")
}

// commentLine reports a line that is only a comment.
func commentLine(s string) bool {
	return strings.HasPrefix(s, "//") || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "*") || strings.HasPrefix(s, "/*")
}

// maxLocations bounds the places kept per finding.
const maxLocations = 5

// Options narrow a scan.
type Options struct {
	// GoDirs, if set, are the only directories (relative to the scanned
	// one) whose Go files are scanned: the packages of one program (see
	// GoPackageDirs). Files of other languages are scanned as usual.
	GoDirs map[string]bool
}

// ScanDir scans the source files under dir (tests, vendored code and
// comments left out).
func ScanDir(dir string, opts Options) (*Scan, error) {
	s := &Scan{Files: map[string]int{}}
	found := map[string]*Finding{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		if d.IsDir() {
			if path != dir && skipDir[d.Name()] && !opts.GoDirs[rel] {
				return filepath.SkipDir
			}
			return nil
		}
		lang, ok := extensions[filepath.Ext(path)]
		if !ok || isTest(d.Name()) || !d.Type().IsRegular() {
			return nil
		}
		if lang == "Go" && opts.GoDirs != nil && !opts.GoDirs[filepath.Dir(rel)] {
			return nil
		}
		s.Files[lang]++
		return scanFile(path, rel, append(languages[lang], common...), found)
	})
	if err != nil {
		return nil, err
	}
	for _, f := range found {
		s.Findings = append(s.Findings, *f)
	}
	sort.Slice(s.Findings, func(i, j int) bool {
		a, b := s.Findings[i], s.Findings[j]
		if a.Kind != b.Kind {
			return kindOrder(a.Kind) < kindOrder(b.Kind)
		}
		return a.Value < b.Value
	})
	return s, nil
}

func kindOrder(k Kind) int {
	for i, x := range Kinds {
		if x == k {
			return i
		}
	}
	return len(Kinds)
}

func scanFile(path, rel string, rules []rule, found map[string]*Finding) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || commentLine(line) {
			continue
		}
		for _, r := range rules {
			for _, m := range r.re.FindAllStringSubmatch(line, -1) {
				v := m[0]
				if r.value != nil {
					v = r.value(m)
				}
				if v == "" {
					continue
				}
				kind := r.kind
				if kind == KindPath && binPath.MatchString(v) {
					kind = KindProgram // a program named by its path
				}
				key := string(kind) + "\x00" + v
				fd := found[key]
				if fd == nil {
					fd = &Finding{Kind: kind, Value: v}
					found[key] = fd
				}
				if len(fd.Locations) < maxLocations {
					text := line
					if len(text) > 160 {
						text = text[:160] + "…"
					}
					fd.Locations = append(fd.Locations, Location{File: rel, Line: n, Text: text})
				}
			}
		}
	}
	return sc.Err()
}
