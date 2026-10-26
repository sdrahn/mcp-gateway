package approvalpage

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Branding is what the page shows of the system it runs on, as Cockpit's
// login page does: the operating system's logo from Cockpit's branding,
// its name from os-release, and the host name. All of it is optional.
type Branding struct {
	OSName string // PRETTY_NAME
	Host   string
	Logo   []byte // PNG
	Icon   []byte // ICO
}

// CockpitBranding is where Cockpit keeps its branding.
const CockpitBranding = "/usr/share/cockpit/branding"

// OSRelease are the os-release files, in the order they are read:
// /usr/lib's first, which the gateway's SELinux domain reads as any file
// in /usr (/etc/os-release is a link to it on SUSE).
var OSRelease = []string{"/usr/lib/os-release", "/etc/os-release"}

// maxImage bounds a logo or icon.
const maxImage = 1 << 20

var (
	pngMagic = []byte("\x89PNG\r\n\x1a\n")
	icoMagic = []byte("\x00\x00\x01\x00")
)

// LoadBranding reads the branding at start, from the directories of root
// Cockpit takes it from, the first that has a file winning: <ID>-<VARIANT_ID>,
// <ID>, each of ID_LIKE, default. The logo is logo.png (else
// apple-touch-icon.png), the icon favicon.ico; a file that is not a PNG or
// ICO of at most 1 MiB is skipped.
func LoadBranding(root string, osRelease []string) Branding {
	rel := readOSRelease(osRelease)
	b := Branding{OSName: rel["PRETTY_NAME"]}
	if b.OSName == "" {
		b.OSName = strings.TrimSpace(rel["NAME"] + " " + rel["VERSION"])
	}
	b.Host, _ = os.Hostname()
	var dirs []string
	if id := rel["ID"]; id != "" {
		if v := rel["VARIANT_ID"]; v != "" {
			dirs = append(dirs, id+"-"+v)
		}
		dirs = append(dirs, id)
	}
	dirs = append(dirs, strings.Fields(rel["ID_LIKE"])...)
	dirs = append(dirs, "default")
	find := func(magic []byte, names ...string) []byte {
		for _, d := range dirs {
			if strings.ContainsAny(d, "/\\") || d == "." || d == ".." {
				continue
			}
			for _, n := range names {
				if data := readImage(filepath.Join(root, d, n), magic); data != nil {
					return data
				}
			}
		}
		return nil
	}
	b.Logo = find(pngMagic, "logo.png", "apple-touch-icon.png")
	b.Icon = find(icoMagic, "favicon.ico")
	return b
}

// readImage reads path if it starts with magic and is at most maxImage.
func readImage(path string, magic []byte) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxImage+1))
	if err != nil || len(data) > maxImage || !bytes.HasPrefix(data, magic) {
		return nil
	}
	return data
}

// readOSRelease reads the first of paths that exists (os-release(5)).
func readOSRelease(paths []string) map[string]string {
	out := map[string]string{}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(io.LimitReader(f, 64<<10))
		for sc.Scan() {
			k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
			if !ok || strings.HasPrefix(k, "#") {
				continue
			}
			if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
				v = v[1 : len(v)-1]
			}
			out[k] = strings.ReplaceAll(v, `\"`, `"`)
		}
		_ = f.Close()
		return out
	}
	return out
}

// image serves a branding image, which browsers may keep for a day.
func image(data []byte, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if data == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "max-age=86400")
		_, _ = w.Write(data)
	}
}
