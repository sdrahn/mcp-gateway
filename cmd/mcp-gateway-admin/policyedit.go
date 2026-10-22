package main

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/policydata"
)

// policyCmd is "policy show" and "policy write": the role data for
// Cockpit's role editor, which leaves YAML to this command
// (docs/architecture.md, roadmap step 37 B).
type policyCmd struct {
	stdout, stderr     io.Writer
	path, def, shipped string
}

// origin says where the role data in force comes from.
func (c policyCmd) origin(file string) string {
	switch {
	case file == c.def:
		return "default"
	case strings.EqualFold(filepath.Ext(file), ".yaml"):
		return "yaml"
	}
	return "json"
}

func (c policyCmd) emit(v any) {
	enc := json.NewEncoder(c.stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// show prints the role data in force. Data that does not parse is shown
// as its text, with the error, for the raw editor to fix.
func (c policyCmd) show() int {
	file, ignored := policydata.InForceOr(c.path, c.def)
	out := map[string]any{"file": file, "origin": c.origin(file), "ignored": nonNil(ignored)}
	text, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		out["data"], out["yaml"] = map[string]any{}, ""
		c.emit(out)
		return 0
	}
	if err != nil {
		sayf(c.stderr, "mcp-gateway-admin: %v", err)
		return exitRefused
	}
	_, data, _, err := policydata.Read(file)
	if err != nil {
		out["error"], out["data"] = err.Error(), nil
		if c.origin(file) != "json" {
			out["yaml"] = string(text)
		}
		c.emit(out)
		return 0
	}
	out["data"] = json.RawMessage(data)
	y := text
	if c.origin(file) == "json" {
		if y, err = policydata.ToYAML(data, header(file)); err != nil {
			out["error"] = err.Error()
		}
	}
	out["yaml"] = string(y)
	c.emit(out)
	return 0
}

// header is the comment of a data.yaml made from file (data.json or the
// shipped default).
func header(file string) string {
	return "Role data (docs/user-guide/06-policy.md), started from " + file + "."
}

// write checks the role data on in (JSON, or YAML if asYAML) and writes
// it to data.yaml next to c.path, unless dryRun.
func (c policyCmd) write(in io.Reader, asYAML, dryRun bool) int {
	target := filepath.Join(filepath.Dir(c.path), "data.yaml")
	res := map[string]any{"file": target, "written": false, "problems": []string{}}
	fail := func(problems ...string) int {
		res["problems"] = problems
		c.emit(res)
		return exitRefused
	}
	raw, err := io.ReadAll(in)
	if err != nil {
		return fail(err.Error())
	}
	data, y := raw, raw
	if asYAML {
		if data, err = policydata.ToJSON(raw); err != nil {
			return fail("not valid YAML: " + err.Error())
		}
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return fail("not a JSON object: " + err.Error())
	}
	shipped, _, err := policydata.ShippedRoles(c.shipped)
	if err != nil {
		return fail(err.Error())
	}
	problems, err := policydata.CheckWith(data, shipped)
	if err != nil {
		return fail(err.Error())
	}
	res["data"] = json.RawMessage(data)
	if len(problems) > 0 {
		return fail(problems...)
	}
	if !asYAML {
		// Into data.yaml where it is; else a new one.
		file, _ := policydata.InForceOr(c.path, c.def)
		if file == target {
			base, err := os.ReadFile(target)
			if err != nil {
				return fail(err.Error())
			}
			if y, err = policydata.UpdateYAML(base, data); err != nil {
				return fail(err.Error())
			}
		} else if y, err = policydata.ToYAML(data, header(file)); err != nil {
			return fail(err.Error())
		}
	}
	res["yaml"] = string(y)
	if _, err := os.Stat(filepath.Join(filepath.Dir(c.path), "data.json")); err == nil {
		res["ignored"] = []string{filepath.Join(filepath.Dir(c.path), "data.json")}
	}
	if dryRun {
		c.emit(res)
		return 0
	}
	mode := fs.FileMode(0o644)
	if fi, err := os.Stat(target); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := writeFileAtomic(target, y, mode); err != nil {
		return fail(err.Error())
	}
	res["written"] = true
	c.emit(res)
	return 0
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
