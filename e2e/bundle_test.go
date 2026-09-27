package e2e

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// dropInArgs returns the opa arguments of the ExecStart= line in a
// shipped mcp-opa.service drop-in, with paths replaced.
func dropInArgs(t *testing.T, file string, replace ...string) []string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(b), "\\\n", " ")
	for _, line := range strings.Split(text, "\n") {
		cmd, ok := strings.CutPrefix(line, "ExecStart=/usr/bin/opa ")
		if !ok {
			continue
		}
		cmd = strings.NewReplacer(replace...).Replace(cmd)
		return strings.Fields(cmd)
	}
	t.Fatalf("no opa ExecStart= in %s", file)
	return nil
}

func signingKey(t *testing.T, dir string) (key, pub string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	key, pub = filepath.Join(dir, "signing.pem"), filepath.Join(dir, "verify.pem")
	writeFile(t, key, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	writeFile(t, pub, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})))
	return key, pub
}

// tamper rewrites the bundle with edit applied to its data.json, keeping
// the signature.
func tamper(t *testing.T, bundle string, edit func(string) string) {
	t.Helper()
	f, err := os.Open(bundle)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	tw := tar.NewWriter(zw)
	tr := tar.NewReader(zr)
	found := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimPrefix(h.Name, "/") == "data.json" {
			body = []byte(edit(string(body)))
			h.Size = int64(len(body))
			found = true
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	_ = f.Close()
	if !found {
		t.Fatal("no data.json in the bundle")
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// opaGet queries OPA's REST API on a unix socket.
func opaGet(t *testing.T, sock, path string, v any) {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	resp, err := c.Get("http://opa" + path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

func TestSignedBundle(t *testing.T) {
	opa := opaBinary(t)
	home := t.TempDir()
	writeFile(t, filepath.Join(home, "hello.txt"), "hello bundle")
	keys := t.TempDir()
	key, pub := signingKey(t, keys)

	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	rbac := `{"roles": {"reader": {"permissions": [{"server": "fs", "tool": "read_*"}]}},
	  "bindings": {"groups": {}, "users": {"` + me.Username + `": ["reader"]}}}`
	var bundle, sock string
	// Build the bundle with mcp-policy-bundle from the policy logic and
	// the role data, and start OPA as the shipped drop-in does.
	e := setupWith(t, rbac, map[string]string{"fs": home}, "", func(tmp, opaSock string) []string {
		bundleDir := filepath.Join(tmp, "bundle")
		bundle, sock = filepath.Join(bundleDir, "policy.tar.gz"), opaSock
		cmd := exec.Command("sh", filepath.Join("..", "tools", "mcp-policy-bundle"),
			"-k", key, "-r", "e2e-1", "-n", "-o", bundle,
			"-V", filepath.Join("..", "policy"), "-L", filepath.Join(tmp, "data"))
		cmd.Env = append(os.Environ(), "OPA="+opa)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("mcp-policy-bundle: %v\n%s", err, out)
		}
		if err := os.Link(pub, filepath.Join(bundleDir, "verify.pem")); err != nil {
			t.Fatal(err)
		}
		return dropInArgs(t, filepath.Join("..", "packaging", "opa", "signed-bundle.conf"),
			"/run/mcp-gateway/opa.sock", opaSock, "/etc/mcp-gateway/bundle", bundleDir)
	})

	t.Run("revision active", func(t *testing.T) {
		var resp struct {
			Result map[string]struct {
				Manifest struct{ Revision string } `json:"manifest"`
			} `json:"result"`
		}
		opaGet(t, sock, "/v1/data/system/bundles", &resp)
		if len(resp.Result) != 1 {
			t.Fatalf("bundles: %+v", resp.Result)
		}
		for _, b := range resp.Result {
			if b.Manifest.Revision != "e2e-1" {
				t.Fatalf("revision %q", b.Manifest.Revision)
			}
		}
	})

	t.Run("decisions from the bundle", func(t *testing.T) {
		c := newClient(t, e.connect, e.gwSock, "fs")
		c.initialize(nil)
		text, isErr := toolResult(t, c.call(2, "read_file", map[string]any{"path": filepath.Join(home, "hello.txt")}))
		if isErr || text != "hello bundle" {
			t.Fatalf("got %q %v", text, isErr)
		}
		text, isErr = toolResult(t, c.call(3, "write_file", map[string]any{"path": filepath.Join(home, "x"), "content": "x"}))
		if !isErr || !strings.Contains(text, "no matching permission") {
			t.Fatalf("got %q %v", text, isErr)
		}
	})

	t.Run("tampered bundle refused", func(t *testing.T) {
		tamper(t, bundle, func(s string) string {
			return strings.Replace(s, `"bindings":{`, `"bindings":{"extra":{},`, 1)
		})
		args := dropInArgs(t, filepath.Join("..", "packaging", "opa", "signed-bundle.conf"),
			"/run/mcp-gateway/opa.sock", filepath.Join(t.TempDir(), "opa.sock"), "/etc/mcp-gateway/bundle", filepath.Dir(bundle))
		cmd := exec.Command(opa, args...)
		done := make(chan error, 1)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(out.String(), "digest mismatch") {
				t.Fatalf("exit %v: %s", err, out.String())
			}
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			t.Fatal("OPA started with a tampered bundle")
		}
	})
}
