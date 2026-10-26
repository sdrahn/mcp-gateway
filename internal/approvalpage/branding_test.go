package approvalpage

import (
	"bytes"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Branding is looked for as Cockpit does: <ID>-<VARIANT_ID>, <ID>, each
// of ID_LIKE, default; the first directory with the file wins, and a
// file that is no PNG (or ICO) is skipped.
func TestLoadBranding(t *testing.T) {
	root := t.TempDir()
	rel := filepath.Join(t.TempDir(), "os-release")
	writeTestFile(t, rel, "# comment\nNAME=\"openSUSE Leap Micro\"\nID=\"opensuse-leap-micro\"\nVARIANT_ID=\"\"\nID_LIKE=\"suse opensuse\"\nPRETTY_NAME=\"openSUSE Leap Micro 6.2\"\n")
	png := string(pngMagic) + "logo"
	writeTestFile(t, filepath.Join(root, "suse", "logo.png"), "not a png")
	writeTestFile(t, filepath.Join(root, "opensuse", "logo.png"), png+"-opensuse")
	writeTestFile(t, filepath.Join(root, "default", "logo.png"), png+"-default")
	writeTestFile(t, filepath.Join(root, "default", "favicon.ico"), string(icoMagic)+"icon")
	b := LoadBranding(root, []string{filepath.Join(t.TempDir(), "missing"), rel})
	if b.OSName != "openSUSE Leap Micro 6.2" {
		t.Errorf("os name %q", b.OSName)
	}
	if !bytes.HasSuffix(b.Logo, []byte("-opensuse")) {
		t.Errorf("logo %q, want opensuse's (suse's is no PNG)", b.Logo)
	}
	if !bytes.HasSuffix(b.Icon, []byte("icon")) {
		t.Errorf("icon %q", b.Icon)
	}
	if h, _ := os.Hostname(); b.Host != h {
		t.Errorf("host %q", b.Host)
	}

	// <ID>-<VARIANT_ID> before <ID>; apple-touch-icon.png without a logo.png.
	writeTestFile(t, rel, "ID=sles\nVARIANT_ID=sap\nNAME=SLES\nVERSION=\"16.0\"\n")
	writeTestFile(t, filepath.Join(root, "sles", "logo.png"), png+"-sles")
	writeTestFile(t, filepath.Join(root, "sles-sap", "apple-touch-icon.png"), png+"-sap")
	b = LoadBranding(root, []string{rel})
	if b.OSName != "SLES 16.0" || !bytes.HasSuffix(b.Logo, []byte("-sap")) {
		t.Errorf("sles-sap: %q %q", b.OSName, b.Logo)
	}

	// An ID that is a path does not leave root; too large is skipped.
	writeTestFile(t, rel, "ID=../etc\n")
	writeTestFile(t, filepath.Join(root, "default", "logo.png"), png+strings.Repeat("x", maxImage))
	if b = LoadBranding(root, []string{rel}); b.Logo != nil {
		t.Errorf("logo %d bytes", len(b.Logo))
	}
	// Without Cockpit's branding or os-release: nothing, without error.
	if b = LoadBranding(filepath.Join(root, "none"), nil); b.OSName != "" || b.Logo != nil || b.Icon != nil {
		t.Errorf("nothing: %+v", b)
	}
}

// The page's palette is the Cockpit plugin's, light and dark.
func TestPaletteIsThePlugins(t *testing.T) {
	css, err := os.ReadFile(filepath.Join("..", "..", "cockpit", "mcp-gateway", "gateway.css"))
	if err != nil {
		t.Fatal(err)
	}
	vars := regexp.MustCompile(`(--[a-z-]+):\s*([^;]+);`)
	palettes := func(s string) (light, dark map[string]string) {
		i := strings.Index(s, "@media (prefers-color-scheme: dark)")
		if i < 0 {
			t.Fatalf("no dark palette in %.80s", s)
		}
		read := func(part string) map[string]string {
			m := map[string]string{}
			for _, v := range vars.FindAllStringSubmatch(part, -1) {
				m[v[1]] = v[2]
			}
			return m
		}
		end := i + strings.Index(s[i:], "\n}")
		return read(s[:i]), read(s[i:end])
	}
	pl, pd := palettes(string(css))
	gl, gd := palettes(style)
	for name, ps := range map[string][2]map[string]string{"light": {pl, gl}, "dark": {pd, gd}} {
		plugin, page := ps[0], ps[1]
		if len(plugin) == 0 {
			t.Fatalf("%s: no colors in gateway.css", name)
		}
		for k, v := range plugin {
			if page[k] != v {
				t.Errorf("%s %s: the page has %q, the plugin %q", name, k, page[k], v)
			}
		}
		if len(page) != len(plugin) {
			t.Errorf("%s: the page has %d colors, the plugin %d", name, len(page), len(plugin))
		}
	}
}

// The page shows the logo (served by itself, img-src 'self') and, to the
// signed-in only, the system's name and host name.
func TestPageBranding(t *testing.T) {
	f := newFixture(t, func(pg *Page) {
		pg.Branding = Branding{OSName: "openSUSE Tumbleweed", Host: "rpi-micro", Logo: append(append([]byte{}, pngMagic...), "logo"...), Icon: icoMagic}
	})
	c := f.browser(t)
	code, body, hdr := get(t, c, f.srv.URL+"/approvals/")
	if code != http.StatusOK || !strings.Contains(body, `<img src="/approvals/static/logo.png"`) ||
		!strings.Contains(body, "openSUSE Tumbleweed · rpi-micro") || !strings.Contains(body, `href="/approvals/static/favicon.ico"`) {
		t.Errorf("inbox: %d %s", code, body)
	}
	if !strings.Contains(hdr.Get("Content-Security-Policy"), "img-src 'self'") {
		t.Errorf("CSP %q", hdr.Get("Content-Security-Policy"))
	}
	code, body, hdr = get(t, c, f.srv.URL+"/approvals/static/logo.png")
	if code != http.StatusOK || hdr.Get("Content-Type") != "image/png" || !strings.HasPrefix(body, string(pngMagic)) {
		t.Errorf("logo: %d %q %q", code, hdr.Get("Content-Type"), body)
	}
	// Signed out: the logo, but not which system.
	post(t, c, f.srv.URL+"/approvals/logout", url.Values{"csrf": {csrfOf(t, body0(t, c, f.srv.URL))}}, nil)
	_, body, _ = get(t, f.srv.Client(), f.srv.URL+"/approvals/signed-out")
	if !strings.Contains(body, "logo.png") || strings.Contains(body, "rpi-micro") {
		t.Errorf("signed out: %s", body)
	}
	// Without a logo: none, and 404.
	f = newFixture(t)
	if code, body, _ := get(t, f.srv.Client(), f.srv.URL+"/approvals/signed-out"); code != http.StatusOK || strings.Contains(body, "<img") {
		t.Errorf("no logo: %d %s", code, body)
	}
	if code, _, _ := get(t, f.srv.Client(), f.srv.URL+"/approvals/static/logo.png"); code != http.StatusNotFound {
		t.Errorf("no logo: %d", code)
	}
}

// body0 is the inbox's body for c.
func body0(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	_, body, _ := get(t, c, base+"/approvals/")
	return body
}
