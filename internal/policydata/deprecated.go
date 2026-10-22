package policydata

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// JSON as configuration is deprecated since 1.6 and no longer read in 1.7
// (docs/architecture.md, roadmap step 38, D10): the role data and the data
// of custom Rego are YAML, and JSONFiles finds what is not.

// DeprecatedSince is the release that deprecated configuration in JSON.
const DeprecatedSince = "1.6"

// JSONFiles returns the files in JSON read as configuration, sorted: the
// role data in force in each directory below rbacDir (DefaultDir) that is
// a data.json, and every *.json file OPA loads from policyDir
// (/etc/mcp-gateway/policy), that is outside directories named rbac,
// which mcp-opa.service ignores (--ignore rbac). A directory that does not
// exist has none.
func JSONFiles(policyDir, rbacDir string) ([]string, error) {
	found := map[string]bool{}
	walk := func(top string, visit func(path string, d fs.DirEntry) error) error {
		err := filepath.WalkDir(top, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) && path == top {
					return filepath.SkipAll
				}
				return err
			}
			return visit(path, d)
		})
		return err
	}
	err := walk(policyDir, func(path string, d fs.DirEntry) error {
		if d.IsDir() {
			if d.Name() == "rbac" && path != policyDir {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) == ".json" && d.Type().IsRegular() {
			found[path] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	err = walk(rbacDir, func(path string, d fs.DirEntry) error {
		if !d.IsDir() {
			return nil
		}
		file, _ := InForce(filepath.Join(path, Names[1]))
		if filepath.Ext(file) != ".json" {
			return nil
		}
		if fi, err := os.Stat(file); err == nil && fi.Mode().IsRegular() {
			found[file] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(found))
	for f := range found {
		files = append(files, f)
	}
	sort.Strings(files)
	return files, nil
}

// JSONDeprecation is the warning about configuration in JSON without the
// file's name, for a log line that names it apart.
func JSONDeprecation() string {
	return fmt.Sprintf("configuration in JSON is deprecated since %s and will no longer be read in the next minor release", DeprecatedSince)
}

// ConvertCommand is the command that converts file to YAML.
func ConvertCommand(file string) string {
	return "mcp-gateway-admin policy convert " + file
}

// JSONWarning is the warning about file, with its name and the command
// that converts it.
func JSONWarning(file string) string {
	return fmt.Sprintf("%s: %s: convert it to YAML with %s", file, JSONDeprecation(), ConvertCommand(file))
}
