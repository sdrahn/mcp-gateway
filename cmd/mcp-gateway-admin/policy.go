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

FILE is the role data in JSON (default: ` + policydata.DefaultPath + `).
The YAML goes next to it as data.yaml (or FILE with .yaml), which is then
in force; FILE stays as it is, ignored, until you remove it. The data and
the order of keys stay the same.

`

func runPolicy(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet("mcp-gateway-admin policy", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.Usage = func() {
		_, _ = fmt.Fprint(stderr, policyUsage)
		fset.PrintDefaults()
	}
	f := adminFlags{fs: fset}
	out := f.fs.String("o", "", `where to write the YAML ("-": standard output)`)
	force := f.fs.Bool("force", false, "replace the YAML file if it exists")
	words, rc := f.parse(args)
	if rc >= 0 {
		return rc
	}
	if len(words) == 0 || words[0] != "convert" || len(words) > 2 {
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
