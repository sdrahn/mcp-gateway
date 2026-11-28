package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// server_discovery: container mode only; the prefix defaults to the
// namespace's, and may be set empty.
func TestServerDiscovery(t *testing.T) {
	const c = "deployment: container\n"
	g, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", c+httpYAML+
		"server_discovery:\n  namespaces:\n    - namespace: team-a\n    - namespace: mcp\n      prefix: \"\"\n    - namespace: b\n      prefix: x-\n"))
	if err != nil {
		t.Fatal(err)
	}
	d := g.ServerDiscovery.WithDefaults()
	if !d.Enabled() || d.Selector != DefaultDiscoverySelector || d.APIServer != DefaultKubernetesAPIServer ||
		d.TokenFile != DefaultKubernetesTokenFile || d.CAFile != DefaultKubernetesCAFile {
		t.Errorf("server_discovery %+v", d)
	}
	if p := []string{d.Namespaces[0].PrefixOf(), d.Namespaces[1].PrefixOf(), d.Namespaces[2].PrefixOf()}; strings.Join(p, ",") != "team-a-,,x-" {
		t.Errorf("prefixes %q", p)
	}
	h, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", "{}\n"))
	if err != nil || h.ServerDiscovery.Enabled() {
		t.Errorf("default: %v %+v", err, h.ServerDiscovery)
	}
	const sd = "server_discovery:\n  namespaces:\n    - namespace: team-a\n"
	for content, want := range map[string]string{
		sd: "server_discovery: only in container mode",
		c + httpYAML + "server_discovery:\n  selector: a=b\n":                                                                           "server_discovery: set namespaces, or nothing",
		c + httpYAML + "server_discovery:\n  namespaces:\n    - namespace: Team\n":                                                      `namespaces[0].namespace: "Team" is not a namespace name`,
		c + httpYAML + "server_discovery:\n  namespaces:\n    - namespace: a\n    - namespace: a\n":                                     "server_discovery.namespaces: a twice",
		c + httpYAML + sd + "      prefix: A-\n":                                                                                        `namespaces[0].prefix: "A-" is not the start of a server's name`,
		c + httpYAML + "server_discovery:\n  namespaces:\n    - namespace: a\n      prefix: x-\n    - namespace: b\n      prefix: x-\n": `a and b have the same prefix "x-"`,
		c + httpYAML + sd + "  selector: \"a in (b)\"\n":                                                                                "server_discovery.selector",
		c + httpYAML + sd + "  selector: \"=b\"\n":                                                                                      "server_discovery.selector",
	} {
		if _, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", content)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", content, err, want)
		}
	}
	for _, sel := range []string{"mcp-gateway.io/server=true", "a=b,!c,d!=e", "team", "app.kubernetes.io/part-of==tools"} {
		if _, err := LoadGateway(writeFile(t, t.TempDir(), "gateway.yaml", c+httpYAML+sd+"  selector: \""+sel+"\"\n")); err != nil {
			t.Errorf("selector %q: %v", sel, err)
		}
	}
}

// MaskedNames: the empty files where LoadBackends reads them, a later
// directory's replacing an earlier one's.
func TestMaskedNames(t *testing.T) {
	vendor, admin := t.TempDir(), t.TempDir()
	for dir, files := range map[string]map[string]string{
		vendor: {"a.yaml": "", "b.yaml": "name: b\n", "c.yaml": ""},
		admin:  {"b.yaml": "", "c.yaml": "name: c\n", "d.yaml": "", "notes.txt": ""},
	} {
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	got, err := MaskedNames(vendor, admin)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !got["a"] || !got["b"] || !got["d"] {
		t.Errorf("masked %v, want a, b, d", got)
	}
}
