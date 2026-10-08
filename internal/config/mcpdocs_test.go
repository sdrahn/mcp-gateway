package config

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// mcpDocsTools are the tools of mcp-docs with --fs-compat
// (https://github.com/sdrahn/mcp-docs).
var mcpDocsTools = []string{"list_docs", "outline", "search", "read_section", "read_lines",
	"outline_file", "search_text", "read_text_file", "search_files", "list_directory"}

func installed(t *testing.T, in string) []byte {
	t.Helper()
	b, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.NewReplacer("@BINDIR@", "/usr/bin", "@LIBEXECDIR@", "/usr/libexec", "@DATADIR@", "/usr/share").
		Replace(string(b)))
}

// gateway-docs on mcp-docs replaces the shipped definition from the
// administrator's directory, keeps its domain, account and Landlock
// rules, and its instructions name only tools mcp-docs has (or
// gateway-admin's).
func TestGatewayDocsOnMcpDocs(t *testing.T) {
	vendor, admin := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(vendor, "gateway-docs.yaml"),
		installed(t, "../../packaging/fs-server/gateway-docs.yaml.in"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(admin, "gateway-docs.yaml"),
		installed(t, "../../packaging/fs-server/gateway-docs-mcp-docs.yaml.in"), 0o644); err != nil {
		t.Fatal(err)
	}
	bs, err := LoadBackends(vendor, admin)
	if err != nil {
		t.Fatal(err)
	}
	b := bs["gateway-docs"]
	if b == nil || b.Command[0] != "/usr/bin/mcp-docs" || !slices.Contains(b.Command, "--fs-compat") ||
		b.SELinuxType != "mcpsrv_docs_t" || b.RunAs != "dynamic" || b.Network ||
		b.Landlock == nil || !slices.Equal(b.Landlock.Read, []string{"/usr/share/mcp-gateway/docs"}) || b.Landlock.Write != nil {
		t.Fatalf("gateway-docs %+v", b)
	}
	i := slices.Index(b.Command, "--collection")
	if i < 0 || !strings.HasPrefix(b.Command[i+1], "mcp-gateway=/usr/share/mcp-gateway/docs:") {
		t.Errorf("collection: %v", b.Command)
	}
	i = slices.Index(b.Command, "--instructions")
	if i < 0 {
		t.Fatalf("no --instructions: %v", b.Command)
	}
	known := append(slices.Clone(mcpDocsTools), "show_config", "check_config")
	for _, name := range regexp.MustCompile(`\b[a-z]+(?:_[a-z]+)+\b`).FindAllString(b.Command[i+1], -1) {
		if !slices.Contains(known, name) {
			t.Errorf("the instructions name %q, which mcp-docs does not have", name)
		}
	}
	if !strings.Contains(b.Command[i+1], "mcp-gateway/README.md") {
		t.Errorf("the instructions do not start with the index: %s", b.Command[i+1])
	}
}

// The collection file names only keys mcp-docs reads, and its root and
// index are what the Makefile installs.
func TestMcpDocsCollection(t *testing.T) {
	var c map[string]any
	if err := yaml.Unmarshal(installed(t, "../../packaging/docs/mcp-docs-collection.yaml.in"), &c); err != nil {
		t.Fatal(err)
	}
	for k := range c {
		if !slices.Contains([]string{"name", "title", "root", "description", "index", "include", "exclude", "also", "instructions"}, k) {
			t.Errorf("key %q: mcp-docs does not read it", k)
		}
	}
	if c["root"] != "/usr/share/mcp-gateway/docs" {
		t.Errorf("root %v", c["root"])
	}
	// The Makefile installs docs/ there, CHANGELOG.md beside it.
	if _, err := os.Stat(filepath.Join("../../docs", c["index"].(string))); err != nil {
		t.Errorf("index: %v", err)
	}
	if s, _ := c["instructions"].(string); !strings.Contains(s, "gateway-admin") {
		t.Errorf("instructions: %q", s)
	}
}
