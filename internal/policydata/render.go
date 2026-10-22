package policydata

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// The role data as OPA loads it (docs/architecture.md, roadmap step 37):
// OPA does not read DefaultDir itself (mcp-opa.service: --ignore rbac),
// as it would merge data.yaml and data.json where both exist; the
// renderer (mcp-policy-render, as root) writes the file in force of each
// directory below DefaultDir as JSON to RenderDir, which OPA loads as
// data.mcp.rbac. The gateway cannot write RenderDir.
const (
	DefaultDir = "/etc/mcp-gateway/policy/rbac"
	RenderDir  = "/run/mcp-opa/rbac"
)

// renderName is the name of a rendered file: OPA loads it whatever the
// format of its source.
const renderName = "data.json"

// A Source is a file in force below the role data's directory and what it
// renders to.
type Source struct {
	Rel     string   // its directory, relative to the role data's ("." for the top)
	File    string   // the file in force
	Ignored []string // the files next to it that are not
	JSON    []byte   // its content as JSON
}

// A Plan is what the role data below a directory renders to.
type Plan struct {
	Sources []Source
	// Problems are the schema's findings on the top directory's role data
	// (CheckWith): reported, and rendered all the same, as OPA has loaded
	// role data that does not check (the policy treats what it does not
	// know as absent).
	Problems []string
	// Unloaded are the other files below the directory that OPA loaded
	// when it read the directory itself (*.json, *.yaml, *.yml, *.rego)
	// and that are not rendered: reported.
	Unloaded []string
}

// PlanRender reads the role data in force below dir, the top and every
// directory under it (rbac/<name>/, chapter 12), with the shipped roles
// below shippedDir for the schema check. Where the top has no role data
// (or dir does not exist), def (the shipped default, DefaultData; "":
// none) is in force there, taken whole. A file that does not parse, or is
// not an object, is an error: nothing is to be rendered then, and the
// last rendering stays in force (as OPA keeps its previous data when a
// file does not load).
func PlanRender(dir, def, shippedDir string) (Plan, error) {
	var p Plan
	var errs []error
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && path == dir {
				return filepath.SkipAll
			}
			return err
		}
		if !d.IsDir() {
			switch strings.ToLower(filepath.Ext(path)) {
			case ".json", ".yaml", ".yml", ".rego":
				if !slices.Contains(Names, d.Name()) {
					p.Unloaded = append(p.Unloaded, path)
				}
			}
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		file, ignored := InForce(filepath.Join(path, Names[1]))
		if _, err := os.Stat(file); errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err := p.add(rel, file, ignored, shippedDir); err != nil {
			errs = append(errs, err)
		}
		return nil
	})
	if err != nil {
		return Plan{}, err
	}
	if !slices.ContainsFunc(p.Sources, func(s Source) bool { return s.Rel == "." }) && def != "" {
		if _, err := os.Stat(def); err == nil {
			if err := p.add(".", def, nil, shippedDir); err != nil {
				errs = append(errs, err)
			}
			// The top first, as the walk has it.
			n := len(p.Sources) - 1
			if n > 0 && p.Sources[n].Rel == "." {
				p.Sources = append([]Source{p.Sources[n]}, p.Sources[:n]...)
			}
		}
	}
	if len(errs) > 0 {
		return Plan{}, errors.Join(errs...)
	}
	return p, nil
}

// add adds file, the role data in force in the directory rel, to the
// plan; the top's (".") is checked against the schema.
func (p *Plan) add(rel, file string, ignored []string, shippedDir string) error {
	f, data, _, err := Read(file)
	if err != nil {
		return err
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("%s: not valid JSON: %w", f, err)
	}
	if _, ok := v.(map[string]any); !ok {
		return fmt.Errorf("%s: not an object", f)
	}
	p.Sources = append(p.Sources, Source{Rel: rel, File: f, Ignored: ignored, JSON: data})
	if rel != "." {
		return nil
	}
	shipped, _, err := ShippedRoles(shippedDir)
	if err != nil {
		return err
	}
	problems, err := CheckWith(data, shipped)
	if err != nil {
		return err
	}
	for _, pr := range problems {
		p.Problems = append(p.Problems, f+": "+pr)
	}
	return nil
}

// Stale returns how out differs from the plan's rendering: the files to
// write and those to remove, relative to out, sorted. Nothing differs
// when both are empty.
func (p Plan) Stale(out string) (write, remove []string, err error) {
	want := p.files()
	for rel, data := range want {
		have, err := os.ReadFile(filepath.Join(out, rel))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, nil, err
		}
		if err != nil || !bytes.Equal(have, data) {
			write = append(write, rel)
		}
	}
	err = filepath.WalkDir(out, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && path == out {
				return filepath.SkipAll
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(out, path)
		if err != nil {
			return err
		}
		if _, ok := want[rel]; !ok {
			remove = append(remove, rel)
		}
		return nil
	})
	sort.Strings(write)
	sort.Strings(remove)
	return write, remove, err
}

// files are the plan's rendered files, relative to the output directory.
func (p Plan) files() map[string][]byte {
	out := map[string][]byte{}
	for _, s := range p.Sources {
		out[filepath.Join(s.Rel, renderName)] = s.JSON
	}
	return out
}

// Render writes the plan to out: each file that changed, through a
// temporary file renamed into place (a name OPA does not load), and
// removes what the plan no longer has, empty directories included. It
// returns the files written and removed, relative to out.
func (p Plan) Render(out string) (written, removed []string, err error) {
	write, remove, err := p.Stale(out)
	if err != nil {
		return nil, nil, err
	}
	want := p.files()
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, nil, err
	}
	for _, rel := range write {
		if err := writeAtomic(filepath.Join(out, rel), want[rel]); err != nil {
			return written, removed, err
		}
		written = append(written, rel)
	}
	for _, rel := range remove {
		if err := os.Remove(filepath.Join(out, rel)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return written, removed, err
		}
		removed = append(removed, rel)
	}
	return written, removed, removeEmptyDirs(out)
}

// writeAtomic writes data to path through a temporary file next to it.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// ".render-*", without an extension OPA loads.
	f, err := os.CreateTemp(dir, ".render-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// removeEmptyDirs removes the empty directories below top, deepest first.
func removeEmptyDirs(top string) error {
	var dirs []string
	err := filepath.WalkDir(top, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != top {
			dirs = append(dirs, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(dirs, func(i, j int) bool { return strings.Count(dirs[i], "/") > strings.Count(dirs[j], "/") })
	for _, d := range dirs {
		if entries, err := os.ReadDir(d); err == nil && len(entries) == 0 {
			if err := os.Remove(d); err != nil {
				return err
			}
		}
	}
	return nil
}
