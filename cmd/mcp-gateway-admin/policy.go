package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/policydata"
)

const policyUsage = `usage: mcp-gateway-admin policy convert [FILE] [options]   write data in JSON as YAML (or back, --to json)
       mcp-gateway-admin policy show [options]             the role data in force, as JSON
       mcp-gateway-admin policy write [options] < DATA     check role data and write it to data.yaml

convert: FILE is the role data in JSON (default: ` + policydata.DefaultPath + `),
or a data file of custom Rego below /etc/mcp-gateway/policy; JSON there is
no longer read since 1.7, and the gateway denies every request while some
is left over. The data and the order of keys stay the same. The YAML goes next to FILE, with .yaml for .json:
role data's is then in force, and FILE stays as it is, ignored, until you
remove it; for other data, which OPA loads itself and refuses twice, FILE
is removed. --to json converts YAML back, without its comments (for an
earlier release; default FILE: data.yaml of the role data).

show: {"file", "origin" (yaml, json or default), "ignored", "data", "yaml"
(the YAML text: the file's, or the data converted), "error"} of the role
data in force (json: a data.json without data.yaml, no longer read, shown
converted for saving as data.yaml).

write: DATA on standard input is the role data as JSON, written into
data.yaml where it keeps the comments and order of what is unchanged;
with --yaml, YAML written as it is. Data the schema refuses is not
written (exit status 1). Prints {"file", "written", "problems", "data",
"yaml", "ignored"}. --dry-run only checks.

`

func runPolicy(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("mcp-gateway-admin policy", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.Usage = func() {
		_, _ = fmt.Fprint(stderr, policyUsage)
		fset.PrintDefaults()
	}
	f := adminFlags{fs: fset}
	out := f.fs.String("o", "", `convert: where to write the converted file ("-": standard output)`)
	force := f.fs.Bool("force", false, "convert: replace the file it writes if it exists")
	to := f.fs.String("to", "yaml", "convert: yaml (from JSON) or json (from YAML, to go back to an earlier release)")
	asYAML := f.fs.Bool("yaml", false, "write: the data on standard input is YAML, written as it is")
	dryRun := f.fs.Bool("dry-run", false, "write: check only")
	pc := policyCmd{stdout: stdout, stderr: stderr}
	f.fs.StringVar(&pc.path, "policy-data", policydata.DefaultPath, "the role data; convert: also the local policy two directories up")
	f.fs.StringVar(&pc.def, "default-policy-data", policydata.DefaultData, "show, write: the shipped default role data")
	f.fs.StringVar(&pc.shipped, "shipped-policy", policydata.DefaultShippedDir, "write: the shipped policy, for the setups' roles")
	words, rc := f.parse(args)
	if rc >= 0 {
		return rc
	}
	switch {
	case len(words) == 1 && words[0] == "show":
		return pc.show()
	case len(words) == 1 && words[0] == "write":
		return pc.write(stdin, *asYAML, *dryRun)
	case len(words) == 0 || words[0] != "convert" || len(words) > 2:
		f.fs.Usage()
		return exitUsage
	}
	src := ""
	if len(words) == 2 {
		src = words[1]
	}
	return pc.convert(src, *out, *to, *force)
}

// convert is "policy convert": src (role data or the data of custom Rego)
// from JSON to YAML, or with to "json" back, to dst ("": next to src,
// "-": standard output). Configuration in JSON is no longer read since 1.7
// (step 38); --to json is for going back to an earlier release. Role data
// converted next to its file is in force by the file's name (InForce),
// the other stays, ignored; the other data below the policy directory
// OPA loads itself, and the gateway is blocked while it finds JSON there
// (as OPA of 1.6 or earlier refuses both), so there the source goes once
// the conversion is written.
func (c policyCmd) convert(src, dst, to string, force bool) int {
	fail := func(format string, a ...any) int {
		sayf(c.stderr, "mcp-gateway-admin: "+format, a...)
		return exitRefused
	}
	toJSON := false
	switch to {
	case "yaml":
	case "json":
		toJSON = true
	default:
		return fail("--to is yaml or json, not %q", to)
	}
	rbacDir := filepath.Dir(c.path)
	if src == "" {
		src = c.path
		if toJSON {
			src = filepath.Join(rbacDir, policydata.Names[0])
		}
	}
	ext := strings.ToLower(filepath.Ext(src))
	isYAML := ext == ".yaml" || ext == ".yml"
	switch {
	case !toJSON && isYAML:
		return fail("%s is YAML already", src)
	case toJSON && ext == ".json":
		return fail("%s is JSON already", src)
	}
	data, err := os.ReadFile(src)
	if errors.Is(err, fs.ErrNotExist) && !toJSON && src == c.path {
		return fail("%s does not exist: the shipped default (%s) is in force; to change it, copy it to %s and edit that",
			src, c.def, filepath.Join(rbacDir, policydata.Names[0]))
	}
	if err != nil {
		return fail("%v", err)
	}
	newExt := ".yaml"
	if toJSON {
		newExt = ".json"
	}
	if dst == "" {
		dst = strings.TrimSuffix(src, filepath.Ext(src)) + newExt
	}
	custom := c.customData(src)
	var conv []byte
	if toJSON {
		j, err := policydata.ToJSON(data)
		if err == nil {
			var buf bytes.Buffer
			if err = json.Indent(&buf, j, "", "  "); err == nil {
				conv = append(buf.Bytes(), '\n')
			}
		}
		if err != nil {
			return fail("%s: %v", src, err)
		}
	} else {
		header := "Role data (docs/user-guide/06-policy.md), converted from " + filepath.Base(src) +
			"\nby mcp-gateway-admin policy convert."
		if custom {
			header = "Policy data, converted from " + filepath.Base(src) + " by mcp-gateway-admin policy convert."
		} else if dst != "-" && filepath.Base(dst) == "data.yaml" && filepath.Dir(dst) == filepath.Dir(src) && filepath.Base(src) == "data.json" {
			header += " data.json next to this file is ignored\nwhile it exists; remove it when you no longer need it."
		}
		if conv, err = policydata.ToYAML(data, header); err != nil {
			return fail("%s: %v", src, err)
		}
	}
	if dst == "-" {
		_, _ = c.stdout.Write(conv)
		return 0
	}
	if _, err := os.Stat(dst); err == nil && !force {
		return fail("%s exists; --force replaces it", dst)
	}
	mode := fs.FileMode(0o644)
	if fi, err := os.Stat(src); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := writeFileAtomic(dst, conv, mode); err != nil {
		return fail("%v", err)
	}
	sayf(c.stdout, "wrote %s", dst)
	if custom && filepath.Dir(dst) == filepath.Dir(src) {
		// OPA keeps the data it had while it finds both, then loads dst.
		if err := os.Remove(src); err != nil {
			return fail("%s and %s both exist, which OPA refuses: %v", src, dst, err)
		}
		if err := nudgeOPA(c.policyDir()); err != nil {
			sayf(c.stderr, "mcp-gateway-admin: %v: OPA may not see %s until the next change below %s (systemctl restart mcp-opa.service)", err, dst, c.policyDir())
		}
		back := "--to json "
		if toJSON {
			back = ""
		}
		sayf(c.stdout, "removed %s: OPA loads the data files below %s itself, and the same data twice is an error (mcp-gateway-admin policy convert %s%s brings it back)",
			src, c.policyDir(), back, dst)
		if toJSON {
			sayf(c.stdout, "%s: %v: this release denies every request while it exists", dst, policydata.ErrJSON)
		}
		return 0
	}
	inForce, ignored := policydata.InForce(dst)
	switch {
	case inForce == dst:
		for _, ig := range ignored {
			sayf(c.stdout, "%s is in force now; %s is ignored (remove it when you no longer need it)", dst, ig)
		}
	case slices.Contains(policydata.Names, filepath.Base(dst)):
		sayf(c.stdout, "%s stays in force while it exists; to go back to 1.4 or earlier, which load both files and refuse them, remove it", inForce)
	}
	return 0
}

// nudgeOPA makes OPA (opa run --watch) look at dir, the local policy,
// again: it creates and removes a file there. OPA watches only the
// directories it loaded a file from (and the one it was given), so it
// misses a data.yaml written into a directory made after it started that
// held only data in JSON, which it ignores (since 1.7), until a change in
// a watched directory makes it look again.
var nudgeOPA = func(dir string) error {
	f, err := os.CreateTemp(dir, ".mcp-gateway-admin-*")
	if err != nil {
		return err
	}
	_ = f.Close()
	return os.Remove(f.Name())
}

// policyDir is the directory of the local policy OPA loads
// (/etc/mcp-gateway/policy, above the role data's).
func (c policyCmd) policyDir() string { return filepath.Dir(filepath.Dir(c.path)) }

// customData reports whether file is data OPA loads from the local policy
// directory itself: below it, and not below a directory named rbac (the
// role data's, which mcp-opa.service ignores).
func (c policyCmd) customData(file string) bool {
	abs, err := filepath.Abs(file)
	if err != nil {
		return false
	}
	dir, err := filepath.Abs(c.policyDir())
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(dir, abs)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return false
	}
	return !slices.Contains(strings.Split(filepath.Dir(rel), string(filepath.Separator)), "rbac")
}

// writeFileAtomic writes data to path through a temporary file next to
// it, which never has a name the role data's readers take.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".new-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
