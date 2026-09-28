// Package pseudo pseudonymizes personal and confidential data in what MCP
// servers return before it reaches the agent (and the LLM behind it), and
// re-identifies the pseudonyms in arguments the agent sends back, where
// policy allows it.
//
// A pseudonym is a token such as "[EMAIL_3]": the class of the value and a
// number. Within one Vault (one MCP session) the same value always gets the
// same token, so the model can still relate records and refer to them in
// later calls. The mapping lives only in memory and ends with the session.
//
// Values are found by
//   - field rules: the value of a JSON object key, at any depth, also inside
//     JSON that a tool returns as text ("fields": {"email": "email"});
//   - built-in detectors for well-formed identifiers (e-mail addresses,
//     IBANs and payment card numbers with their checksums, international
//     phone numbers, IP addresses);
//   - named regular expressions ("patterns": {"customer": "CUST-[0-9]{6}"}).
//
// Detection is deterministic: it finds what the rules describe and nothing
// else. It is a risk reduction for data flowing to external models, not a
// guarantee that no personal data leaves.
package pseudo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Spec is the "pseudonymize" obligation as policy writes it.
type Spec struct {
	// Detect names built-in detectors (see Detectors).
	Detect []string `json:"detect,omitempty"`
	// Patterns are named regular expressions; the name, upper-cased, is
	// the token class.
	Patterns map[string]string `json:"patterns,omitempty"`
	// Fields maps JSON object keys to token classes.
	Fields map[string]string `json:"fields,omitempty"`
}

// Empty reports whether s asks for nothing.
func (s *Spec) Empty() bool {
	return s == nil || len(s.Detect)+len(s.Patterns)+len(s.Fields) == 0
}

type detector struct {
	class string
	re    *regexp.Regexp
	valid func(string) bool // nil: every match counts
}

// Detectors are the built-in detectors by name.
var Detectors = map[string]detector{
	"email":       {class: "EMAIL", re: regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}`)},
	"iban":        {class: "IBAN", re: regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,3})?)\b`), valid: validIBAN},
	"credit_card": {class: "CARD", re: regexp.MustCompile(`\b[0-9](?:[ \-]?[0-9]){12,18}\b`), valid: validLuhn},
	"phone":       {class: "PHONE", re: regexp.MustCompile(`\+[1-9][0-9]{0,2}(?:[ \-/]?\(?[0-9]{1,5}\)?){2,6}`), valid: validPhone},
	"ipv4":        {class: "IP", re: regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b`)},
	"ipv6":        {class: "IP", re: regexp.MustCompile(`(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}`), valid: validIPv6},
}

var (
	nameRE  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	tokenRE = regexp.MustCompile(`\[([A-Z][A-Z0-9_]{0,31})_([0-9]+)\]`)
)

// Compiled is a Spec ready to be applied.
type Compiled struct {
	detectors []detector
	fields    map[string]string // key → class
}

// Compile validates s. A nil or empty Spec compiles to nil (nothing to do).
func Compile(s *Spec) (*Compiled, error) {
	if s.Empty() {
		return nil, nil
	}
	c := &Compiled{fields: map[string]string{}}
	names := append([]string(nil), s.Detect...)
	sort.Strings(names)
	for _, name := range names {
		d, ok := Detectors[name]
		if !ok {
			return nil, fmt.Errorf("pseudonymize: unknown detector %q", name)
		}
		c.detectors = append(c.detectors, d)
	}
	for _, name := range sortedKeys(s.Patterns) {
		if !nameRE.MatchString(name) {
			return nil, fmt.Errorf("pseudonymize: pattern name %q must match %s", name, nameRE)
		}
		re, err := regexp.Compile(s.Patterns[name])
		if err != nil {
			return nil, fmt.Errorf("pseudonymize: pattern %s: %w", name, err)
		}
		if re.MatchString("") {
			return nil, fmt.Errorf("pseudonymize: pattern %s matches the empty string", name)
		}
		c.detectors = append(c.detectors, detector{class: strings.ToUpper(name), re: re})
	}
	for key, class := range s.Fields {
		if key == "" {
			return nil, errors.New("pseudonymize: empty field name")
		}
		if !nameRE.MatchString(class) {
			return nil, fmt.Errorf("pseudonymize: class %q of field %q must match %s", class, key, nameRE)
		}
		c.fields[key] = strings.ToUpper(class)
	}
	return c, nil
}

// Stats counts the values replaced, by token class. Values that got no
// pseudonym because the vault was full count as "REDACTED".
type Stats map[string]int

// String renders s as "EMAIL:2 PERSON:1", sorted by class.
func (s Stats) String() string {
	parts := make([]string, 0, len(s))
	for _, class := range sortedKeys(s) {
		parts = append(parts, class+":"+strconv.Itoa(s[class]))
	}
	return strings.Join(parts, " ")
}

// DefaultLimit bounds the pseudonyms one vault holds. Further values are
// replaced irreversibly ("[EMAIL_REDACTED]") rather than passed through.
const DefaultLimit = 10000

// Vault holds the pseudonyms of one session.
type Vault struct {
	limit int

	mu      sync.Mutex
	byValue map[string]string // value key → token
	byToken map[string]any    // token → original value (string or json.Number)
	next    map[string]int    // class → last number used
}

// NewVault returns an empty vault holding at most limit pseudonyms
// (DefaultLimit if limit <= 0).
func NewVault(limit int) *Vault {
	if limit <= 0 {
		limit = DefaultLimit
	}
	return &Vault{limit: limit, byValue: map[string]string{}, byToken: map[string]any{}, next: map[string]int{}}
}

// Len returns the number of pseudonyms held.
func (v *Vault) Len() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.byToken)
}

// token returns the pseudonym for value. Caller holds v.mu.
func (v *Vault) token(class string, value any, st Stats) string {
	key := valueKey(value)
	if t, ok := v.byValue[key]; ok {
		st[tokenClass(t)]++
		return t
	}
	if len(v.byToken) >= v.limit {
		st["REDACTED"]++
		return "[" + class + "_REDACTED]"
	}
	v.next[class]++
	t := "[" + class + "_" + strconv.Itoa(v.next[class]) + "]"
	v.byValue[key] = t
	v.byToken[t] = value
	st[class]++
	return t
}

func valueKey(value any) string {
	if n, ok := value.(json.Number); ok {
		return "n:" + n.String()
	}
	return "s:" + fmt.Sprint(value)
}

func tokenClass(t string) string {
	if m := tokenRE.FindStringSubmatch(t); m != nil {
		return m[1]
	}
	return "REDACTED"
}

// Apply pseudonymizes the JSON document doc with c. A nil c returns doc
// unchanged.
func (v *Vault) Apply(c *Compiled, doc json.RawMessage) (json.RawMessage, Stats, error) {
	st := Stats{}
	if c == nil {
		return doc, st, nil
	}
	var x any
	if err := decode(doc, &x); err != nil {
		return nil, st, fmt.Errorf("pseudonymize: %w", err)
	}
	v.mu.Lock()
	x = v.walk(c, x, "", st)
	v.mu.Unlock()
	out, err := encode(x, false)
	if err != nil {
		return nil, st, fmt.Errorf("pseudonymize: %w", err)
	}
	return out, st, nil
}

// walk pseudonymizes x. With class set, every scalar in x is a value of
// that class (x is, or lies below, a field named by a field rule).
// Caller holds v.mu.
func (v *Vault) walk(c *Compiled, x any, class string, st Stats) any {
	switch t := x.(type) {
	case map[string]any:
		// Binary content (images, audio, resource blobs) is base64: left
		// alone, detectors could corrupt it.
		// Keys in order, so that token numbers do not depend on map order.
		_, binary := t["mimeType"]
		for _, k := range sortedKeys(t) {
			val := t[k]
			switch {
			case k == "blob", k == "data" && binary, k == "type", k == "mimeType":
				continue
			case class != "":
				t[k] = v.walk(c, val, class, st)
			default:
				if fc, ok := c.fields[k]; ok {
					t[k] = v.walk(c, val, fc, st)
				} else {
					t[k] = v.walk(c, val, "", st)
				}
			}
		}
		return t
	case []any:
		for i := range t {
			t[i] = v.walk(c, t[i], class, st)
		}
		return t
	case string:
		if class != "" {
			if t == "" {
				return t
			}
			return v.token(class, t, st)
		}
		return v.text(c, t, st)
	case json.Number:
		if class != "" {
			return v.token(class, t, st)
		}
	}
	return x
}

// text pseudonymizes free text: JSON embedded as text is walked (so field
// rules apply to it), everything else is scanned by the detectors.
// Caller holds v.mu.
func (v *Vault) text(c *Compiled, s string, st Stats) string {
	if len(c.fields) > 0 {
		trimmed := strings.TrimSpace(s)
		if (strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")) && json.Valid([]byte(trimmed)) {
			var x any
			if decode([]byte(trimmed), &x) == nil {
				x = v.walk(c, x, "", st)
				if out, err := encode(x, strings.Contains(trimmed, "\n")); err == nil {
					return string(out)
				}
			}
		}
	}
	return v.scan(c.detectors, s, st)
}

type match struct {
	start, end int
	class      string
}

// scan replaces what the detectors find in s. Overlapping matches are
// resolved in favour of the earliest, then the longest one.
// Caller holds v.mu.
func (v *Vault) scan(ds []detector, s string, st Stats) string {
	var ms []match
	for _, d := range ds {
		for _, loc := range d.re.FindAllStringIndex(s, -1) {
			if d.valid == nil || d.valid(s[loc[0]:loc[1]]) {
				ms = append(ms, match{loc[0], loc[1], d.class})
			}
		}
	}
	if len(ms) == 0 {
		return s
	}
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].start != ms[j].start {
			return ms[i].start < ms[j].start
		}
		return ms[i].end > ms[j].end
	})
	var b strings.Builder
	pos := 0
	for _, m := range ms {
		if m.start < pos {
			continue // overlaps a replaced match
		}
		b.WriteString(s[pos:m.start])
		b.WriteString(v.token(m.class, s[m.start:m.end], st))
		pos = m.end
	}
	b.WriteString(s[pos:])
	return b.String()
}

// Reidentify replaces pseudonyms of this vault in the named arguments by
// the original values; other arguments stay as they are. An argument that
// is exactly one token gets the original value with its type (string or
// number); tokens inside longer text are replaced by the value's text.
// It returns a copy of args (args itself is not modified), the names of
// the arguments that changed, and the number of tokens replaced.
func (v *Vault) Reidentify(args map[string]any, names []string) (map[string]any, []string, int) {
	if len(args) == 0 || len(names) == 0 {
		return args, nil, 0
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make(map[string]any, len(args))
	for k, val := range args {
		out[k] = val
	}
	var changed []string
	total := 0
	for _, name := range names {
		val, ok := args[name]
		if !ok {
			continue
		}
		nv, n := v.restore(deepCopy(val))
		if n > 0 {
			out[name] = nv
			changed = append(changed, name)
			total += n
		}
	}
	sort.Strings(changed)
	return out, changed, total
}

// restore re-identifies tokens in x. Caller holds v.mu.
func (v *Vault) restore(x any) (any, int) {
	switch t := x.(type) {
	case string:
		if orig, ok := v.byToken[t]; ok {
			return orig, 1
		}
		n := 0
		s := tokenRE.ReplaceAllStringFunc(t, func(tok string) string {
			if orig, ok := v.byToken[tok]; ok {
				n++
				return fmt.Sprint(orig)
			}
			return tok
		})
		return s, n
	case map[string]any:
		n := 0
		for k, val := range t {
			var m int
			t[k], m = v.restore(val)
			n += m
		}
		return t, n
	case []any:
		n := 0
		for i := range t {
			var m int
			t[i], m = v.restore(t[i])
			n += m
		}
		return t, n
	}
	return x, 0
}

func deepCopy(x any) any {
	switch t := x.(type) {
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, v := range t {
			m[k] = deepCopy(v)
		}
		return m
	case []any:
		s := make([]any, len(t))
		for i, v := range t {
			s[i] = deepCopy(v)
		}
		return s
	}
	return x
}

func decode(b []byte, x any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(x); err != nil {
		return err
	}
	if d.More() {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

func encode(x any, indent bool) ([]byte, error) {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if indent {
		e.SetIndent("", "  ")
	}
	if err := e.Encode(x); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- validators -----------------------------------------------------------

func validIBAN(s string) bool {
	s = strings.ReplaceAll(s, " ", "")
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rearranged := s[4:] + s[:4]
	var digits strings.Builder
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			digits.WriteString(strconv.Itoa(int(r-'A') + 10))
		default:
			return false
		}
	}
	n, ok := new(big.Int).SetString(digits.String(), 10)
	return ok && new(big.Int).Mod(n, big.NewInt(97)).Int64() == 1
}

func validLuhn(s string) bool {
	var ds []int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			ds = append(ds, int(r-'0'))
		}
	}
	if len(ds) < 13 || len(ds) > 19 {
		return false
	}
	sum := 0
	for i := range ds {
		d := ds[len(ds)-1-i]
		if i%2 == 1 {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// validPhone requires 7 to 15 digits (E.164 allows at most 15).
func validPhone(s string) bool {
	n := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			n++
		}
	}
	return n >= 7 && n <= 15
}

// validIPv6 accepts addresses with at least two groups and five hex
// digits, so that "::", "d::" (as in "std::string") or times are left alone.
func validIPv6(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() != nil {
		return false
	}
	groups, digits := 0, 0
	for _, g := range strings.Split(s, ":") {
		if g != "" {
			groups++
			digits += len(g)
		}
	}
	return groups >= 2 && digits >= 5
}
