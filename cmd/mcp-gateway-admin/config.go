package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

const configUsage = `usage: mcp-gateway-admin config get KEY [options]        a setting in force, and where it comes from
       mcp-gateway-admin config set KEY VALUE [options]  set it in the command's own drop-in
       mcp-gateway-admin config unset KEY [options]      remove it from that drop-in
       mcp-gateway-admin config show [options]           every setting in force

KEY is a key of gateway.yaml as the file has it (limits.tasks_per_principal);
VALUE is YAML (64, 15m, "a b", [a, b], {kit: "2025-11-25"}); one that
starts with - comes after -- (config set KEY -- -1s). The commands
read the files the gateway reads: /etc/mcp-gateway/gateway.yaml, else the
default in /usr/etc/mcp-gateway, with the drop-ins of
/etc/mcp-gateway/gateway.d over it (user guide, chapter 3).

"config set" writes /etc/mcp-gateway/gateway.d/50-mcp-gateway-admin.yaml,
after checking the whole configuration it makes; it changes nothing when
the check fails or a later drop-in sets the key too. The gateway reloads
the file by itself; the command waits for that and says whether the
setting is in force or takes effect at the next start. "config unset"
removes the key from that file, so that the value below is in force
again. Writing needs root.

Exit status: 0; 1 for an unknown key, a value the check refuses, a key a
later drop-in sets, or a reload that failed; 2 for wrong usage; 3 when the
gateway does not answer (after set and unset, the file is written all the
same, and the gateway reads it when it runs).

Options:
`

// adminDropIn is the drop-in config set writes.
const adminDropIn = "50-mcp-gateway-admin.yaml"

const adminDropInHeader = "Written by mcp-gateway-admin config set and setup http; config unset removes keys again.\n" +
	"Editing by hand works too (user guide, chapter 3)."

// The files the commands read, and how often they look whether the
// gateway reloaded; tests replace them.
var (
	configBases     = []string{config.DefaultConfigPath, config.DefaultVendorConfigPath}
	configDropInDir = config.DefaultDropInDir
	reloadPoll      = 200 * time.Millisecond
)

// configStatus is the part of GET /v1/status the commands read.
type configStatus struct {
	ConfigError   string   `json:"config_error"`
	RestartNeeded []string `json:"restart_needed"`
	// ConfigReloads is missing from a gateway before 1.3.
	ConfigReloads *int `json:"config_reloads"`
}

// setting is a key in force, as get and show print it.
type setting struct {
	Key   string         `json:"key"`
	Value string         `json:"value"` // YAML
	From  *config.Source `json:"from"`  // null: the built-in default
	// Restart tells that the files changed the key since the gateway
	// started; it takes effect at the next start.
	Restart bool `json:"restart_needed,omitempty"`
}

func runConfig(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp-gateway-admin config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, configUsage)
		fs.PrintDefaults()
	}
	f := adminFlags{fs: fs,
		json:   fs.Bool("json", false, "print get and show as JSON"),
		socket: fs.String("socket", "", "the gateway's control socket (default: approvals.control_socket of gateway.yaml)")}
	words, rc := f.parse(args)
	if rc >= 0 {
		return rc
	}
	want := map[string]int{"get": 2, "set": 3, "unset": 2, "show": 1}
	if len(words) == 0 || want[words[0]] != len(words) {
		fs.Usage()
		return exitUsage
	}
	c := &configCmd{stdout: stdout, stderr: stderr, json: *f.json, socket: *f.socket}
	switch words[0] {
	case "get":
		return c.show(words[1])
	case "show":
		return c.show("")
	case "set":
		return c.set(words[1], words[2])
	default:
		return c.unset(words[1])
	}
}

type configCmd struct {
	stdout, stderr io.Writer
	json           bool
	socket         string
}

func (c *configCmd) fail(rc int, format string, a ...any) int {
	sayf(c.stderr, "mcp-gateway-admin: "+format, a...)
	return rc
}

// files returns the base file in force ("" for the built-in defaults)
// and the drop-ins.
func (c *configCmd) files() (string, []string, error) {
	base := ""
	for _, p := range configBases {
		if _, err := os.Stat(p); err == nil {
			base = p
			break
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", nil, err
		}
	}
	dropIns, err := config.DropIns(configDropInDir)
	return base, dropIns, err
}

// status asks the gateway for its status; nil if it does not answer.
func (c *configCmd) status() (*configStatus, error) {
	cc, err := newControlClient(c.socket)
	if err != nil {
		return nil, err
	}
	code, data, err := cc.request(http.MethodGet, "/v1/status", nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("/v1/status: %s", apiMessage(code, data))
	}
	var st configStatus
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("/v1/status: %w", err)
	}
	return &st, nil
}

// show prints key, or every key for "".
func (c *configCmd) show(key string) int {
	keys := config.Keys()
	if key != "" {
		_, section, err := config.KeyType(key)
		if err != nil {
			return c.fail(exitRefused, "%v", err)
		}
		if section {
			return c.fail(exitRefused, "%s is a section: name one of its keys (mcp-gateway-admin config show lists them)", key)
		}
		keys = []string{key}
	}
	base, dropIns, err := c.files()
	if err != nil {
		return c.fail(exitRefused, "%v", err)
	}
	g, err := config.ResolveFiles(base, dropIns)
	if err != nil {
		return c.fail(exitRefused, "the configuration does not load: %v", err)
	}
	sources, err := config.Sources(base, dropIns)
	if err != nil {
		return c.fail(exitRefused, "%v", err)
	}
	st, serr := c.status()
	var out []setting
	for _, k := range keys {
		v, err := config.Value(g, k)
		if err != nil {
			return c.fail(exitRefused, "%v", err)
		}
		s := setting{Key: k, Value: yamlValue(v)}
		if src, ok := sources[k]; ok {
			s.From = &src
		}
		s.Restart = st != nil && slices.Contains(st.RestartNeeded, k)
		out = append(out, s)
	}
	if c.json {
		b, _ := json.MarshalIndent(out, "", "  ")
		_, _ = c.stdout.Write(append(b, '\n'))
	} else {
		for _, s := range out {
			from := "default"
			if s.From != nil {
				from = fmt.Sprintf("%s, line %d", s.From.File, s.From.Line)
			}
			line := fmt.Sprintf("%s: %s  # %s", s.Key, s.Value, from)
			if s.Restart {
				line += "; takes effect at the next start"
			}
			say(c.stdout, line)
		}
	}
	switch {
	case serr != nil:
		sayf(c.stderr, "mcp-gateway-admin: the values of the files; whether the gateway runs with them is not known: %v", serr)
	case st.ConfigError != "":
		sayf(c.stderr, "mcp-gateway-admin: the gateway did not load the files and runs with the configuration it had: %s", st.ConfigError)
	case len(st.RestartNeeded) > 0 && key == "":
		sayf(c.stderr, "mcp-gateway-admin: %s take(s) effect at the next start: systemctl restart mcp-gateway.service", strings.Join(st.RestartNeeded, ", "))
	}
	return 0
}

// yamlValue is v as one line of YAML.
func yamlValue(v reflect.Value) string {
	var n yaml.Node
	if err := n.Encode(v.Interface()); err != nil {
		return fmt.Sprint(v.Interface())
	}
	flowStyle(&n)
	b, err := yaml.Marshal(&n)
	if err != nil {
		return fmt.Sprint(v.Interface())
	}
	return strings.TrimSuffix(string(b), "\n")
}

func flowStyle(n *yaml.Node) {
	if n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode {
		n.Style = yaml.FlowStyle
	}
	for _, c := range n.Content {
		flowStyle(c)
	}
}

func (c *configCmd) set(key, value string) int {
	if rc := c.checkKey(key); rc != 0 {
		return rc
	}
	var v yaml.Node
	if err := yaml.Unmarshal([]byte(value), &v); err != nil {
		return c.fail(exitRefused, "%s: the value is not YAML: %v", key, err)
	}
	val := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: ""}
	if len(v.Content) > 0 {
		val = v.Content[0]
	}
	val.HeadComment, val.LineComment, val.FootComment = "", "", ""
	target := filepath.Join(configDropInDir, adminDropIn)
	doc, old, err := readDropIn(target)
	if err != nil {
		return c.fail(exitRefused, "%v", err)
	}
	setKey(doc.Content[0], strings.Split(key, "."), val)
	return c.write(key, target, doc, old, true, "set "+key+": "+value)
}

func (c *configCmd) unset(key string) int {
	if rc := c.checkKey(key); rc != 0 {
		return rc
	}
	target := filepath.Join(configDropInDir, adminDropIn)
	doc, old, err := readDropIn(target)
	if err != nil {
		return c.fail(exitRefused, "%v", err)
	}
	if !unsetKey(doc.Content[0], strings.Split(key, ".")) {
		say(c.stdout, key+" is not set by "+target+": nothing to unset")
		return 0
	}
	return c.write(key, target, doc, old, false, "unset "+key)
}

// checkKey refuses unknown keys and sections.
func (c *configCmd) checkKey(key string) int {
	_, section, err := config.KeyType(key)
	if err != nil {
		return c.fail(exitRefused, "%v (mcp-gateway-admin config show lists the keys)", err)
	}
	if section {
		return c.fail(exitRefused, "%s is a section: set one of its keys (mcp-gateway-admin config show lists them)", key)
	}
	return 0
}

// readDropIn reads the command's drop-in as a YAML document, a new one
// if there is none; old is its content.
func readDropIn(path string) (*yaml.Node, []byte, error) {
	old, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		return &yaml.Node{Kind: yaml.DocumentNode, HeadComment: adminDropInHeader, Content: []*yaml.Node{m}}, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(old, &doc); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	if doc.Kind == 0 || len(doc.Content) == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, HeadComment: doc.HeadComment, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	if doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("%s: not a mapping of keys", path)
	}
	return &doc, old, nil
}

// setKey sets the key path in the mapping m to v, making the sections on
// the way.
func setKey(m *yaml.Node, path []string, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != path[0] {
			continue
		}
		if len(path) == 1 {
			v.LineComment = m.Content[i+1].LineComment
			m.Content[i+1] = v
			return
		}
		if m.Content[i+1].Kind != yaml.MappingNode {
			m.Content[i+1] = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		}
		setKey(m.Content[i+1], path[1:], v)
		return
	}
	k := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: path[0]}
	if len(path) == 1 {
		m.Content = append(m.Content, k, v)
		return
	}
	sub := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	m.Content = append(m.Content, k, sub)
	setKey(sub, path[1:], v)
}

// unsetKey removes the key path from the mapping m, and the sections it
// leaves empty; it reports whether m had the key.
func unsetKey(m *yaml.Node, path []string) bool {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != path[0] {
			continue
		}
		if len(path) > 1 {
			sub := m.Content[i+1]
			if sub.Kind != yaml.MappingNode || !unsetKey(sub, path[1:]) {
				return false
			}
			if len(sub.Content) > 0 {
				return true
			}
		}
		m.Content = slices.Delete(m.Content, i, i+2)
		return true
	}
	return false
}

// write puts doc in place of target (writeDropIn) and waits for the
// gateway to reload it.
func (c *configCmd) write(key, target string, doc *yaml.Node, old []byte, sets bool, done string) int {
	keys := []string(nil)
	if sets {
		keys = []string{key}
	}
	w, err := c.writeDropIn(target, doc, old, keys)
	if err != nil {
		return c.fail(exitRefused, "%v", err)
	}
	if !w.changed {
		say(c.stdout, "nothing to change: "+target+" has it already")
		return 0
	}
	say(c.stdout, done+" ("+target+")")
	if w.statusErr != nil {
		return c.fail(exitUnreachable, "written; the gateway reads it when it runs: %v", w.statusErr)
	}
	if w.before.ConfigReloads == nil {
		say(c.stdout, "this gateway does not report its reloads: see mcp-gateway-admin doctor whether it took the change")
		return 0
	}
	return c.await(key, *w.before.ConfigReloads, w.next)
}

// dropInWrite is what writeDropIn did.
type dropInWrite struct {
	changed bool            // false: target has it already
	next    *config.Gateway // the configuration with it
	// before is the gateway's status before the write, nil with
	// statusErr if it does not answer.
	before    *configStatus
	statusErr error
}

// writeDropIn puts doc in place of target (removing it if doc is empty),
// after checking the configuration it makes and that no later drop-in
// sets one of keys too, which would win.
func (c *configCmd) writeDropIn(target string, doc *yaml.Node, old []byte, keys []string) (dropInWrite, error) {
	empty := len(doc.Content[0].Content) == 0
	var data []byte
	if !empty {
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(doc); err != nil {
			return dropInWrite{}, err
		}
		_ = enc.Close()
		data = buf.Bytes()
	}
	if old != nil && bytes.Equal(data, old) {
		return dropInWrite{}, nil
	}
	base, dropIns, err := c.files()
	if err != nil {
		return dropInWrite{}, err
	}
	// The drop-ins with the new one in its place, written under a hidden
	// name the gateway does not read.
	tmp := filepath.Join(configDropInDir, "."+filepath.Base(target)+"."+strconv.Itoa(os.Getpid()))
	list := slices.DeleteFunc(slices.Clone(dropIns), func(p string) bool { return p == target })
	if !empty {
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return dropInWrite{}, fmt.Errorf("writing %s: %w", target, err)
		}
		defer func() { _ = os.Remove(tmp) }()
		list = append(list, tmp)
		slices.SortFunc(list, func(a, b string) int {
			return strings.Compare(dropInName(a, tmp, target), dropInName(b, tmp, target))
		})
	}
	next, err := config.ResolveFiles(base, list)
	if err != nil {
		return dropInWrite{}, fmt.Errorf("not changed: %s", strings.ReplaceAll(err.Error(), tmp, target))
	}
	if len(keys) > 0 {
		sources, err := config.Sources(base, list)
		if err != nil {
			return dropInWrite{}, err
		}
		for _, key := range keys {
			if src := sources[key]; src.File != tmp {
				return dropInWrite{}, fmt.Errorf("not changed: %s sets %s too (line %d) and is read after %s, so it would win; change it there",
					src.File, key, src.Line, target)
			}
		}
	}
	before, serr := c.status()
	if empty {
		err = os.Remove(target)
	} else {
		err = os.Rename(tmp, target)
	}
	if err != nil {
		return dropInWrite{}, fmt.Errorf("writing %s: %w", target, err)
	}
	return dropInWrite{changed: true, next: next, before: before, statusErr: serr}, nil
}

// dropInName sorts the hidden file in place of target.
func dropInName(p, tmp, target string) string {
	if p == tmp {
		return filepath.Base(target)
	}
	return filepath.Base(p)
}

// await waits for the gateway to reload (awaitReload) and says what the
// reload left for key.
func (c *configCmd) await(key string, reloads int, next *config.Gateway) int {
	st, err := c.awaitReload(reloads, next)
	switch {
	case err != nil:
		return c.fail(exitUnreachable, "%v", err)
	case st.ConfigError != "":
		return c.fail(exitRefused, "the gateway did not load it and runs with the configuration it had: %s", st.ConfigError)
	case slices.Contains(st.RestartNeeded, key):
		say(c.stdout, key+" takes effect at the next start: systemctl restart mcp-gateway.service (it ends all sessions)")
	default:
		say(c.stdout, key+" is in force")
	}
	return 0
}

// awaitReload waits for the gateway to reload after reloads, at the
// latest a round of polling (policy.watch_interval) and a margin later,
// and returns its status then.
func (c *configCmd) awaitReload(reloads int, next *config.Gateway) (*configStatus, error) {
	wait := next.Policy.WatchInterval
	if wait <= 0 {
		wait = config.DefaultWatchInterval
	}
	deadline := time.Now().Add(2*wait + 5*time.Second)
	for {
		st, err := c.status()
		if err != nil {
			return nil, fmt.Errorf("written; the gateway reads it when it runs: %w", err)
		}
		if st.ConfigReloads != nil && *st.ConfigReloads > reloads {
			return st, nil
		}
		if time.Now().After(deadline) {
			return nil, errors.New("written; the gateway has not reloaded it yet (mcp-gateway-admin doctor tells when it did)")
		}
		time.Sleep(reloadPoll)
	}
}
