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
				Manifest struct {
					Revision string   `json:"revision"`
					Roots    []string `json:"roots"`
				} `json:"manifest"`
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
			// Only data.mcp, so the bundle can share an OPA.
			if len(b.Manifest.Roots) != 1 || b.Manifest.Roots[0] != "mcp" {
				t.Fatalf("roots %q", b.Manifest.Roots)
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

func TestPolicyBundleKeygen(t *testing.T) {
	opa := opaBinary(t)
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found")
	}
	dir := t.TempDir()
	key, bundle := filepath.Join(dir, "keys", "signing.pem"), filepath.Join(dir, "bundle", "policy.tar.gz")
	writeFile(t, filepath.Join(dir, "data", "rbac", "data.json"), `{"roles": {}, "bindings": {}}`)
	run := func(args ...string) (string, error) {
		cmd := exec.Command("sh", append([]string{filepath.Join("..", "tools", "mcp-policy-bundle")}, args...)...)
		cmd.Env = append(os.Environ(), "OPA="+opa)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	build := func() (string, error) {
		return run("-k", key, "-o", bundle, "-n", "-V", filepath.Join("..", "policy"), "-L", filepath.Join(dir, "data"))
	}

	if out, err := build(); err == nil || !strings.Contains(out, "create one with -G") {
		t.Fatalf("build without a key: %v %s", err, out)
	}
	if out, err := run("-G", "-k", key, "-o", bundle); err != nil {
		t.Fatalf("-G: %v %s", err, out)
	}
	for file, mode := range map[string]os.FileMode{key: 0o600, filepath.Join(dir, "bundle", "verify.pem"): 0o644} {
		st, err := os.Stat(file)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != mode {
			t.Errorf("%s: mode %v, want %v", file, st.Mode().Perm(), mode)
		}
	}
	if out, err := run("-G", "-k", key, "-o", bundle); err == nil || !strings.Contains(out, "not replacing") {
		t.Fatalf("second -G: %v %s", err, out)
	}
	if out, err := build(); err != nil {
		t.Fatalf("build with the generated key: %v %s", err, out)
	}
	// Role data that fails its schema is not signed.
	gateway := buildBinary(t, filepath.Join(dir, "bin"), "./cmd/mcp-gateway")
	bad := filepath.Join(dir, "bad")
	writeFile(t, filepath.Join(bad, "rbac", "data.json"), `{"roles": {"r": {"permissions": [{"server": "fs", "tool": "x", "efect": "deny"}]}}}`)
	cmd := exec.Command("sh", filepath.Join("..", "tools", "mcp-policy-bundle"),
		"-k", key, "-o", filepath.Join(dir, "bad.tar.gz"), "-n", "-V", filepath.Join("..", "policy"), "-L", bad)
	cmd.Env = append(os.Environ(), "OPA="+opa, "MCP_GATEWAY="+gateway)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "'efect' not allowed") {
		t.Fatalf("invalid role data: %v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "bad.tar.gz")); err == nil {
		t.Fatal("bundle written for invalid role data")
	}
	// The bundle verifies with the generated verification key.
	cmd = exec.Command(opa, "run", "--server", "--addr", "unix://"+filepath.Join(dir, "opa.sock"), "--bundle",
		"--verification-key", filepath.Join(dir, "bundle", "verify.pem"), bundle)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	waitFor(t, filepath.Join(dir, "opa.sock"))
}

// buildBinary is build, for tests whose local build function shadows it.
var buildBinary = build
