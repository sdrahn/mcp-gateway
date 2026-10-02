package inspect

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Finding is a result of checking role data against a server.
type Finding struct {
	// Level is "error" (a permission names something the server does not
	// have), "warning" (a pattern matches nothing) or "info".
	Level   string `json:"level"`
	Message string `json:"message"`
}

// RoleFile is role data (or a setup's shipped roles: an object with
// "roles") to check, with the name findings refer to it by.
type RoleFile struct {
	Name string
	Data []byte
}

// CheckRoles checks the roles in files against what server offers: a
// permission for the server that names a tool or prompt it does not have
// is an error, a pattern that matches none is a warning. Tools that no
// permission in any of the files names are reported as info.
func CheckRoles(files []RoleFile, server string, res *Result) ([]Finding, error) {
	tools := make([]string, 0, len(res.Tools))
	for _, t := range res.Tools {
		tools = append(tools, t.Name)
	}
	prompts := make([]string, 0, len(res.Prompts))
	for _, p := range res.Prompts {
		prompts = append(prompts, p.Name)
	}
	covered := map[string]bool{}
	out := []Finding{}
	for _, file := range files {
		var doc struct {
			Roles map[string]struct {
				Permissions []map[string]any `json:"permissions"`
			} `json:"roles"`
		}
		if err := json.Unmarshal(file.Data, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", file.Name, err)
		}
		out = checkFile(out, file.Name, doc.Roles, server, tools, prompts, covered)
	}
	var left []string
	for _, t := range tools {
		if !covered[t] {
			left = append(left, t)
		}
	}
	if len(left) > 0 {
		out = append(out, Finding{"info", fmt.Sprintf("tools no permission names: %s", strings.Join(left, ", "))})
	}
	return out, nil
}

func checkFile(out []Finding, name string, roles map[string]struct {
	Permissions []map[string]any `json:"permissions"`
}, server string, tools, prompts []string, covered map[string]bool) []Finding {
	for _, role := range sortedKeys(roles) {
		for i, p := range roles[role].Permissions {
			srv, _ := p["server"].(string)
			if srv == "" || !globMatch(srv, server) {
				continue
			}
			for _, k := range []struct {
				field string
				names []string
				what  string
			}{{"tool", tools, "tool"}, {"prompt", prompts, "prompt"}} {
				pat, ok := p[k.field].(string)
				if !ok {
					continue
				}
				where := fmt.Sprintf("%s: role %s, permission %d", name, role, i)
				if strings.Contains(pat, "${") {
					out = append(out, Finding{"info", fmt.Sprintf("%s: %s %q depends on the user; not checked", where, k.what, pat)})
					continue
				}
				n := 0
				for _, name := range k.names {
					if globMatch(pat, name) {
						n++
						if k.field == "tool" {
							covered[name] = true
						}
					}
				}
				switch {
				case n > 0:
				case !hasGlob(pat):
					out = append(out, Finding{"error", fmt.Sprintf("%s: %s has no %s %q", where, server, k.what, globUnescape(pat))})
				default:
					out = append(out, Finding{"warning", fmt.Sprintf("%s: %s pattern %q matches no %s of %s", where, k.what, pat, k.what, server)})
				}
			}
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var globSpecial = regexp.MustCompile(`[*?\[\]{}]`)

func hasGlob(s string) bool { return globSpecial.MatchString(globEscaped.ReplaceAllString(s, "")) }

var globEscaped = regexp.MustCompile(`\\.`)

func globUnescape(s string) string {
	return globEscaped.ReplaceAllStringFunc(s, func(m string) string { return m[1:] })
}

// globMatch matches name against pattern as the policy does (OPA's
// glob.match with the default delimiter "."): "*" matches within a
// segment, "**" across segments, "?" one character, "[...]" a class
// ("[!...]" negated), "{a,b}" alternatives, "\" escapes. A pattern that
// does not compile matches nothing.
func globMatch(pattern, name string) bool {
	re, err := globRegexp(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(name)
}

func globRegexp(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	depth := 0
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '\\':
			if i+1 < len(pattern) {
				i++
				b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
			}
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString(`[^.]*`)
			}
		case '?':
			b.WriteString(`[^.]`)
		case '[':
			j := strings.IndexByte(pattern[i:], ']')
			if j < 0 {
				return nil, fmt.Errorf("unclosed [ in %q", pattern)
			}
			class := pattern[i+1 : i+j]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + class + "]")
			i += j
		case '{':
			depth++
			b.WriteString("(?:")
		case '}':
			if depth == 0 {
				return nil, fmt.Errorf("unbalanced } in %q", pattern)
			}
			depth--
			b.WriteString(")")
		case ',':
			if depth > 0 {
				b.WriteString("|")
			} else {
				b.WriteString(",")
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("unbalanced { in %q", pattern)
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}
