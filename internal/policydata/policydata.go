// Package policydata checks the role data (roles, bindings, approver
// rules; data.mcp.rbac in OPA) against its JSON Schema, rbac.schema.json,
// and for what a schema cannot express: regular expressions that do not
// compile and references to roles that do not exist. The policy treats
// malformed data as absent, so mistakes would otherwise show up only as
// denied requests.
package policydata

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// DefaultPath is the role data file of a package installation.
const DefaultPath = "/etc/mcp-gateway/policy/rbac/data.json"

// Schema is the JSON Schema (draft-07) of the role data; the packages
// install it as /usr/share/mcp-gateway/schema/rbac.schema.json.
//
//go:embed rbac.schema.json
var Schema []byte

const schemaURL = "https://github.com/sdrahn/mcp-gateway/schema/rbac.schema.json"

var compiled = sync.OnceValues(func() (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(Schema))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaURL, doc); err != nil {
		return nil, err
	}
	return c.Compile(schemaURL)
})

var printer = message.NewPrinter(language.English)

// Check returns the problems in the role data, one line each, starting
// with the location as a JSON pointer; none if it is valid.
func Check(data []byte) ([]string, error) {
	sch, err := compiled()
	if err != nil {
		return nil, fmt.Errorf("policydata: schema: %w", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return []string{"not valid JSON: " + err.Error()}, nil
	}
	if err := sch.Validate(inst); err != nil {
		ve, ok := err.(*jsonschema.ValidationError)
		if !ok {
			return nil, err
		}
		var problems []string
		collect(ve, &problems)
		return dedup(problems), nil
	}
	// Valid against the schema, so the shapes below are known.
	var d rbac
	if err := json.Unmarshal(data, &d); err != nil {
		return []string{err.Error()}, nil
	}
	return d.check(), nil
}

// collect adds the leaf errors of a validation error. The alternatives of
// anyOf and oneOf are joined into one line, since only one of them needs
// to hold.
func collect(e *jsonschema.ValidationError, out *[]string) {
	if len(e.Causes) == 0 {
		*out = append(*out, where(e.InstanceLocation)+e.ErrorKind.LocalizedString(printer))
		return
	}
	switch e.ErrorKind.(type) {
	case *kind.AnyOf, *kind.OneOf:
		var alts []string
		for _, c := range e.Causes {
			var sub []string
			collect(c, &sub)
			for _, s := range sub {
				alts = append(alts, strings.TrimPrefix(s, where(e.InstanceLocation)))
			}
		}
		*out = append(*out, where(e.InstanceLocation)+strings.Join(dedup(alts), ", or "))
	default:
		for _, c := range e.Causes {
			collect(c, out)
		}
	}
}

func where(loc []string) string {
	if len(loc) == 0 {
		return "/: "
	}
	var sb strings.Builder
	for _, s := range loc {
		sb.WriteString("/")
		sb.WriteString(escape(s))
	}
	return sb.String() + ": "
}

func dedup(s []string) []string {
	sort.Strings(s)
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

type rbac struct {
	Roles map[string]struct {
		Permissions []struct {
			Args        map[string]string `json:"args"`
			Obligations struct {
				RedactOutput   stringList            `json:"redact_output"`
				ArgConstraints map[string]stringList `json:"arg_constraints"`
				Pseudonymize   struct {
					Patterns map[string]string `json:"patterns"`
				} `json:"pseudonymize"`
			} `json:"obligations"`
		} `json:"permissions"`
	} `json:"roles"`
	Bindings struct {
		Users  map[string][]string `json:"users"`
		Groups map[string][]string `json:"groups"`
	} `json:"bindings"`
	Approvers map[string][]string `json:"approvers"`
}

// stringList is a string or a list of strings.
type stringList []string

func (l *stringList) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*l = []string{s}
		return nil
	}
	return json.Unmarshal(b, (*[]string)(l))
}

func (d *rbac) check() []string {
	var problems []string
	re := func(loc, expr string) {
		if _, err := regexp.Compile(expr); err != nil {
			problems = append(problems, loc+": invalid regular expression: "+err.Error())
		}
	}
	for _, name := range sortedKeys(d.Roles) {
		for i, p := range d.Roles[name].Permissions {
			base := fmt.Sprintf("/roles/%s/permissions/%d", escape(name), i)
			for _, arg := range sortedKeys(p.Args) {
				re(base+"/args/"+escape(arg), p.Args[arg])
			}
			for j, expr := range p.Obligations.RedactOutput {
				re(fmt.Sprintf("%s/obligations/redact_output/%d", base, j), expr)
			}
			for _, arg := range sortedKeys(p.Obligations.ArgConstraints) {
				for j, expr := range p.Obligations.ArgConstraints[arg] {
					re(fmt.Sprintf("%s/obligations/arg_constraints/%s/%d", base, escape(arg), j), expr)
				}
			}
			for _, class := range sortedKeys(p.Obligations.Pseudonymize.Patterns) {
				re(base+"/obligations/pseudonymize/patterns/"+escape(class), p.Obligations.Pseudonymize.Patterns[class])
			}
		}
	}
	unknown := func(loc, role string) {
		if _, ok := d.Roles[role]; !ok {
			problems = append(problems, fmt.Sprintf("%s: unknown role %q", loc, role))
		}
	}
	for kind, m := range map[string]map[string][]string{"users": d.Bindings.Users, "groups": d.Bindings.Groups} {
		for _, who := range sortedKeys(m) {
			for i, role := range m[who] {
				unknown(fmt.Sprintf("/bindings/%s/%s/%d", kind, escape(who), i), role)
			}
		}
	}
	for _, server := range sortedKeys(d.Approvers) {
		for i, rule := range d.Approvers[server] {
			if role, ok := strings.CutPrefix(rule, "role:"); ok {
				unknown(fmt.Sprintf("/approvers/%s/%d", escape(server), i), role)
			}
		}
	}
	sort.Strings(problems)
	return problems
}

func escape(s string) string { return strings.NewReplacer("~", "~0", "/", "~1").Replace(s) }

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
