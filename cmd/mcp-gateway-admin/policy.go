package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/policydata"
)

const policyUsage = `usage: mcp-gateway-admin policy convert [FILE] [options]   write role data in JSON as YAML
       mcp-gateway-admin policy show [options]             the role data in force, as JSON
       mcp-gateway-admin policy write [options] < DATA     check role data and write it to data.yaml

convert: FILE is the role data in JSON (default: ` + policydata.DefaultPath + `).
The YAML goes next to it as data.yaml (or FILE with .yaml), which is then
in force; FILE stays as it is, ignored, until you remove it. The data and
the order of keys stay the same.

show: {"file", "origin" (yaml, json or default), "ignored", "data", "yaml"
(the YAML text: the file's, or the data converted), "error"} of the role
data in force.

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
	out := f.fs.String("o", "", `convert: where to write the YAML ("-": standard output)`)
	force := f.fs.Bool("force", false, "convert: replace the YAML file if it exists")
	asYAML := f.fs.Bool("yaml", false, "write: the data on standard input is YAML, written as it is")
	dryRun := f.fs.Bool("dry-run", false, "write: check only")
	pc := policyCmd{stdout: stdout, stderr: stderr}
	f.fs.StringVar(&pc.path, "policy-data", policydata.DefaultPath, "show, write: the role data")
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
	src := policydata.DefaultPath
	if len(words) == 2 {
		src = words[1]
	}
	fail := func(format string, a ...any) int {
		sayf(stderr, "mcp-gateway-admin: "+format, a...)
		return exitRefused
	}
	if strings.EqualFold(filepath.Ext(src), ".yaml") || strings.EqualFold(filepath.Ext(src), ".yml") {
		return fail("%s is YAML already", src)
	}
	data, err := os.ReadFile(src)
	if errors.Is(err, fs.ErrNotExist) && src == policydata.DefaultPath {
		return fail("%s does not exist: the shipped default (%s) is in force; to change it, copy it to %s and edit that",
			src, policydata.DefaultData, filepath.Join(filepath.Dir(src), "data.yaml"))
	}
	if err != nil {
		return fail("%v", err)
	}
	dst := *out
	if dst == "" {
		dst = strings.TrimSuffix(src, filepath.Ext(src)) + ".yaml"
	}
	header := "Role data (docs/user-guide/06-policy.md), converted from " + filepath.Base(src) +
		"\nby mcp-gateway-admin policy convert."
	if dst != "-" && filepath.Base(dst) == "data.yaml" && filepath.Dir(dst) == filepath.Dir(src) && filepath.Base(src) == "data.json" {
		header += " data.json next to this file is ignored\nwhile it exists; remove it when you no longer need it."
	}
	y, err := policydata.ToYAML(data, header)
	if err != nil {
		return fail("%s: %v", src, err)
	}
	if dst == "-" {
		_, _ = stdout.Write(y)
		return 0
	}
	if _, err := os.Stat(dst); err == nil && !*force {
		return fail("%s exists; --force replaces it", dst)
	}
	mode := fs.FileMode(0o644)
	if fi, err := os.Stat(src); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := writeFileAtomic(dst, y, mode); err != nil {
		return fail("%v", err)
	}
	inForce, ignored := policydata.InForce(dst)
	sayf(stdout, "wrote %s", dst)
	if inForce == dst {
		for _, ig := range ignored {
			sayf(stdout, "%s is in force now; %s is ignored (remove it when you no longer need it)", dst, ig)
		}
	}
	return 0
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
