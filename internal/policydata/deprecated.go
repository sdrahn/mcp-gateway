package policydata

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// JSON as configuration was deprecated in 1.6 and is no longer read from
// 1.7 on (docs/architecture.md, roadmap step 38, D10): the role data and
// the data of custom Rego are YAML. JSONFiles finds the files in JSON
// that 1.6 read as configuration and that are left over: each is an
// error (ErrJSON), and the policy fails closed while one exists.

// DeprecatedSince is the release that deprecated configuration in JSON,
// RemovedSince the first that no longer reads it.
const (
	DeprecatedSince = "1.6"
	RemovedSince    = "1.7"
)

// ErrJSON is the error of configuration in JSON (JSONError).
var ErrJSON = errors.New("configuration in JSON is no longer read since " + RemovedSince)

// A JSONError is a file in JSON read as configuration until 1.6.
type JSONError struct{ File string }

func (e *JSONError) Error() string { return JSONProblem(e.File) }

// Unwrap makes errors.Is(err, ErrJSON) hold.
func (e *JSONError) Unwrap() error { return ErrJSON }

// JSONFiles returns the files in JSON that 1.6 read as configuration,
// sorted: in each directory below rbacDir (DefaultDir), a data.json
// without a data.yaml (role data in force until 1.6), and every *.json
// file below policyDir (/etc/mcp-gateway/policy) outside directories
// named rbac, which OPA loaded until 1.6 (mcp-opa.service now ignores
// *.json). A directory that does not exist has none.
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

// JSONProblem is the error about file, with its name and the command that
// converts it.
func JSONProblem(file string) string {
	return fmt.Sprintf("%s: %v: convert it to YAML with %s", file, ErrJSON, ConvertCommand(file))
}

// ConvertCommand is the command that converts file to YAML.
func ConvertCommand(file string) string {
	return "mcp-gateway-admin policy convert " + file
}
