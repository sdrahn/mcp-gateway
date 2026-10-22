package httpsetup

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"go.yaml.in/yaml/v3"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// Change is a key of the http block that Write changed.
type Change struct {
	Key, Old, New string
}

// Edit returns data (gateway.yaml) with the http block's keys that the
// setup asks about set from h, and what changed. The rest of the file,
// comments included, stays; data without a document gets the format
// version.
func Edit(data []byte, h config.HTTP) ([]byte, []Change, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
		setScalar(doc.Content[0], "version", strconv.Itoa(config.Version))
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, nil, errors.New("not a mapping of keys")
	}
	block := value(root, "http")
	if block == nil || block.Kind != yaml.MappingNode {
		block = &yaml.Node{Kind: yaml.MappingNode}
		setNode(root, "http", block)
	}
	var changes []Change
	for _, kv := range scalars(h) {
		old := ""
		if n := value(block, kv.key); n != nil {
			old = n.Value
		}
		if kv.v == "" || kv.v == old {
			continue
		}
		setScalar(block, kv.key, kv.v)
		changes = append(changes, Change{"http." + kv.key, old, kv.v})
	}
	if old := sequence(value(block, "scopes")); h.Scopes != nil && fmt.Sprint(old) != fmt.Sprint(h.Scopes) {
		seq := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
		for _, s := range h.Scopes {
			seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: s})
		}
		setNode(block, "scopes", seq)
		changes = append(changes, Change{"http.scopes", fmt.Sprint(old), fmt.Sprint(h.Scopes)})
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), changes, nil
}

// scalars are the keys of the http block the setup asks about, but
// scopes, with their values in h ("" keeps what the block has).
func scalars(h config.HTTP) []struct{ key, v string } {
	return []struct{ key, v string }{
		{"listen", h.Listen}, {"cert_file", h.CertFile}, {"key_file", h.KeyFile},
		{"issuer", h.Issuer}, {"audience", h.Audience},
		{"groups_claim", h.GroupsClaim}, {"local_user_claim", h.LocalUserClaim},
	}
}

// Changes returns what setting the keys the setup asks about from h
// changes in cur, the http block in force (gateway.yaml and its
// drop-ins), as Edit would in a file that has cur.
func Changes(cur, h config.HTTP) []Change {
	var out []Change
	have := map[string]string{}
	for _, kv := range scalars(cur) {
		have[kv.key] = kv.v
	}
	for _, kv := range scalars(h) {
		if kv.v != "" && kv.v != have[kv.key] {
			out = append(out, Change{"http." + kv.key, have[kv.key], kv.v})
		}
	}
	if h.Scopes != nil && fmt.Sprint(cur.Scopes) != fmt.Sprint(h.Scopes) {
		out = append(out, Change{"http.scopes", fmt.Sprint(cur.Scopes), fmt.Sprint(h.Scopes)})
	}
	return out
}

// Node is the YAML value of key (http.listen, …) in h, as Edit writes it.
func Node(h config.HTTP, key string) *yaml.Node {
	if key == "http.scopes" {
		seq := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle, Tag: "!!seq"}
		for _, s := range h.Scopes {
			seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s})
		}
		return seq
	}
	for _, kv := range scalars(h) {
		if "http."+kv.key == key {
			return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: kv.v}
		}
	}
	return nil
}

func value(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func setNode(m *yaml.Node, key string, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = v
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: key}, v)
}

func setScalar(m *yaml.Node, key, v string) {
	if n := value(m, key); n != nil && n.Kind == yaml.ScalarNode {
		n.Value, n.Tag, n.Style = v, "", 0
		return
	}
	setNode(m, key, &yaml.Node{Kind: yaml.ScalarNode, Value: v})
}

func sequence(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	out := []string{}
	for _, c := range n.Content {
		out = append(out, c.Value)
	}
	return out
}

// Write sets the http block in the configuration at path (Edit) and
// returns what changed. A missing file starts from the package default
// (vendor), as the gateway would read it. The new file must load as the
// gateway loads it (config.LoadGateway) before it replaces the old one,
// atomically and with the old one's owner and mode; a new file is 0644,
// as the default is, so that the gateway's account (not root, who runs
// this) can read it; it holds no secrets, only the names of files with
// them. The gateway notices the change and applies what it can without
// a restart (http.listen needs one).
func Write(path, vendor string, h config.HTTP) ([]Change, error) {
	data, err := os.ReadFile(path)
	mode, uid, gid := fs.FileMode(0o644), -1, -1
	switch {
	case err == nil:
		if fi, err := os.Stat(path); err == nil {
			mode = fi.Mode().Perm()
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				uid, gid = int(st.Uid), int(st.Gid)
			}
		}
	case errors.Is(err, os.ErrNotExist):
		if data, err = os.ReadFile(vendor); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	default:
		return nil, err
	}
	out, changes, err := Edit(data, h)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(changes) == 0 {
		return nil, nil
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".gateway.yaml.*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if _, err := config.LoadGateway(tmp.Name()); err != nil {
		return nil, fmt.Errorf("the new configuration does not load, %s is unchanged: %w", path, err)
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return nil, err
	}
	if uid >= 0 {
		if err := os.Chown(tmp.Name(), uid, gid); err != nil {
			return nil, err
		}
	}
	return changes, os.Rename(tmp.Name(), path)
}
