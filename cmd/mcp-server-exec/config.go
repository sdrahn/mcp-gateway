package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sdrahn/mcp-gateway/internal/landlock"
)

// Version is the format version of command files.
const Version = 1

// Limits of a command, and their defaults.
const (
	defaultTimeout   = time.Minute
	maxTimeout       = time.Hour
	defaultMaxOutput = 1 << 20
	maxMaxOutput     = 16 << 20
)

// file is one command file: commands by name.
type file struct {
	Version  int                 `yaml:"version"`
	Commands map[string]*Command `yaml:"commands"`
	// Landlock adds trees the file's commands use beyond those they name
	// (see landlockRules).
	Landlock *landlock.Rules `yaml:"landlock"`
}

// Command is an allowed command: a fixed program and argument vector,
// with placeholders for the arguments the caller gives.
type Command struct {
	Description string            `yaml:"description"`
	Argv        []string          `yaml:"argv"`
	Args        map[string]*Arg   `yaml:"args"`
	Timeout     string            `yaml:"timeout"`
	MaxOutput   int               `yaml:"max_output"`
	ReadOnly    bool              `yaml:"read_only"`
	Env         map[string]string `yaml:"env"`
	Dir         string            `yaml:"dir"`

	Name    string        `yaml:"-"`
	File    string        `yaml:"-"`
	timeout time.Duration // parsed Timeout, or the default
	// landlock is the file's landlock, nil without.
	landlock *landlock.Rules
}

// Arg is an argument the caller gives, substituted for {name} in argv.
type Arg struct {
	Description string `yaml:"description"`
	// Pattern must match the whole value (it is anchored).
	Pattern string  `yaml:"pattern"`
	Default *string `yaml:"default"`
	// AllowDash lets a value start with "-"; otherwise such values are
	// refused, so that a value cannot become an option of the program.
	AllowDash bool `yaml:"allow_dash"`

	re *regexp.Regexp
}

var (
	commandName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	placeholder = regexp.MustCompile(`\{([a-z][a-z0-9_]*)\}`)
	envName     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// load reads the command files in paths: files, or directories whose
// *.yaml files are read in name order. A directory that does not exist
// holds no commands. A name defined twice is an error naming both files.
func load(paths []string) (map[string]*Command, error) {
	cmds := map[string]*Command{}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		files := []string{p}
		if fi.IsDir() {
			if files, err = filepath.Glob(filepath.Join(p, "*.yaml")); err != nil {
				return nil, err
			}
			sort.Strings(files)
		}
		for _, f := range files {
			got, err := loadFile(f)
			if err != nil {
				return nil, err
			}
			for name, c := range got {
				if prev := cmds[name]; prev != nil {
					return nil, fmt.Errorf("command %q is defined in %s and in %s", name, prev.File, f)
				}
				cmds[name] = c
			}
		}
	}
	return cmds, nil
}

func loadFile(path string) (map[string]*Command, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	// An empty file (io.EOF) has no commands.
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	// A file without commands may leave out the version.
	if f.Version != Version && (f.Version != 0 || len(f.Commands) > 0) {
		return nil, fmt.Errorf("%s: version: %d is not supported (this server reads %d)", path, f.Version, Version)
	}
	if l := f.Landlock; l != nil {
		if err := validLandlock(*l); err != nil {
			return nil, fmt.Errorf("%s: landlock: %v", path, err)
		}
	}
	for name, c := range f.Commands {
		if c == nil {
			return nil, fmt.Errorf("%s: command %q: empty", path, name)
		}
		c.Name, c.File, c.landlock = name, path, f.Landlock
		if err := c.validate(); err != nil {
			return nil, fmt.Errorf("%s: command %q: %v", path, name, err)
		}
	}
	return f.Commands, nil
}

func (c *Command) validate() error {
	if !commandName.MatchString(c.Name) {
		return fmt.Errorf("the name must match %s", commandName)
	}
	if len(c.Argv) == 0 {
		return errors.New("argv: empty")
	}
	if prog := c.Argv[0]; !filepath.IsAbs(prog) || filepath.Clean(prog) != prog || placeholder.MatchString(prog) {
		return fmt.Errorf("argv: the program %q must be an absolute, clean path without placeholders", prog)
	}
	used := map[string]bool{}
	for _, a := range c.Argv[1:] {
		for _, m := range placeholder.FindAllStringSubmatch(a, -1) {
			if c.Args[m[1]] == nil {
				return fmt.Errorf("argv: {%s} is not in args", m[1])
			}
			used[m[1]] = true
		}
	}
	for name, a := range c.Args {
		if !placeholder.MatchString("{" + name + "}") {
			return fmt.Errorf("args: name %q must match [a-z][a-z0-9_]*", name)
		}
		if a == nil || a.Pattern == "" {
			return fmt.Errorf("args: %s: pattern is required", name)
		}
		if !used[name] {
			return fmt.Errorf("args: %s is not used in argv", name)
		}
		re, err := regexp.Compile(`^(?:` + a.Pattern + `)$`)
		if err != nil {
			return fmt.Errorf("args: %s: pattern: %v", name, err)
		}
		a.re = re
		if a.Default != nil {
			if err := a.check(*a.Default); err != nil {
				return fmt.Errorf("args: %s: default: %v", name, err)
			}
		}
	}
	c.timeout = defaultTimeout
	if c.Timeout != "" {
		d, err := time.ParseDuration(c.Timeout)
		if err != nil || d <= 0 || d > maxTimeout {
			return fmt.Errorf("timeout: %q must be a duration up to %s", c.Timeout, maxTimeout)
		}
		c.timeout = d
	}
	switch {
	case c.MaxOutput == 0:
		c.MaxOutput = defaultMaxOutput
	case c.MaxOutput < 0 || c.MaxOutput > maxMaxOutput:
		return fmt.Errorf("max_output: between 1 and %d bytes", maxMaxOutput)
	}
	for k := range c.Env {
		if !envName.MatchString(k) {
			return fmt.Errorf("env: invalid name %q", k)
		}
	}
	if c.Dir != "" && !filepath.IsAbs(c.Dir) {
		return fmt.Errorf("dir: %q must be absolute", c.Dir)
	}
	return nil
}

// check reports whether v is an acceptable value of the argument.
func (a *Arg) check(v string) error {
	switch {
	case strings.ContainsRune(v, 0):
		return errors.New("contains a NUL character")
	case !a.AllowDash && strings.HasPrefix(v, "-"):
		return errors.New("must not start with \"-\"")
	case !a.re.MatchString(v):
		return fmt.Errorf("does not match %s", a.Pattern)
	}
	return nil
}

// argv returns the argument vector for the caller's values: every
// argument given or defaulted, checked, and substituted whole into the
// elements naming it. No shell is involved: each element is one argument
// of the program, whatever characters it holds.
func (c *Command) argv(values map[string]string) ([]string, error) {
	for name := range values {
		if c.Args[name] == nil {
			return nil, fmt.Errorf("unknown argument %q", name)
		}
	}
	final := map[string]string{}
	for name, a := range c.Args {
		v, ok := values[name]
		if !ok {
			if a.Default == nil {
				return nil, fmt.Errorf("argument %q is required", name)
			}
			v = *a.Default
		}
		if err := a.check(v); err != nil {
			return nil, fmt.Errorf("argument %q %v", name, err)
		}
		final[name] = v
	}
	out := make([]string, len(c.Argv))
	out[0] = c.Argv[0]
	for i, a := range c.Argv[1:] {
		out[i+1] = placeholder.ReplaceAllStringFunc(a, func(m string) string {
			return final[m[1:len(m)-1]]
		})
	}
	return out, nil
}

// broadPrefixes are tool name prefixes that roles for every server
// commonly allow (the shipped viewer: list_*, read_*, get_*).
var broadPrefixes = []string{"list_", "read_", "get_"}

// warnings are findings that do not make the commands invalid.
func warnings(cmds map[string]*Command) []string {
	var w []string
	for _, name := range sortedNames(cmds) {
		for _, p := range broadPrefixes {
			if strings.HasPrefix(name, p) {
				w = append(w, fmt.Sprintf("%s: names starting with %q are allowed by roles for every server (the shipped viewer allows %s*); choose another name unless that is meant", name, p, p))
			}
		}
	}
	return w
}

func sortedNames(cmds map[string]*Command) []string {
	names := make([]string, 0, len(cmds))
	for n := range cmds {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
