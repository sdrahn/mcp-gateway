package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	src, out, shipped := t.TempDir(), filepath.Join(t.TempDir(), "rbac"), t.TempDir()
	args := []string{"-source", src, "-out", out, "-shipped", shipped, "-default", ""}
	render := func(extra ...string) (int, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		rc := run(context.Background(), append(append([]string{}, args...), extra...), &stdout, &stderr)
		return rc, stderr.String()
	}
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(src, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if rc, msg := render(); rc != 0 || !strings.Contains(msg, "no role data in "+src) {
		t.Errorf("none: %d %s", rc, msg)
	}
	write("data.json", `{"roles": {"old": {"permissions": []}}}`)
	write("data.yaml", "roles: {new: {permissions: []}}\nbindings: {users: {alice: [nope]}}\n")
	if rc, msg := render("-check"); rc != 1 || !strings.Contains(msg, "not current: data.yaml") {
		t.Errorf("check before: %d %s", rc, msg)
	}
	rc, msg := render()
	if rc != 0 || !strings.Contains(msg, "rendered data.yaml") ||
		!strings.Contains(msg, filepath.Join(src, "data.json")+" is ignored: "+filepath.Join(src, "data.yaml")+" is in force") ||
		!strings.Contains(msg, `warning: `+filepath.Join(src, "data.yaml")) {
		t.Errorf("render: %d %s", rc, msg)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "data.yaml")); !strings.Contains(string(b), `"new"`) {
		t.Errorf("rendered %s", b)
	}
	if rc, msg := render("-check"); rc != 0 || !strings.Contains(msg, out+" is current") {
		t.Errorf("check after: %d %s", rc, msg)
	}

	// Broken YAML: exit status 1, the last rendering kept.
	write("data.yaml", "roles: [\n")
	if rc, msg := render(); rc != 1 || !strings.Contains(msg, "the last rendering in "+out+" stays in force") {
		t.Errorf("broken: %d %s", rc, msg)
	}
	if b, _ := os.ReadFile(filepath.Join(out, "data.yaml")); !strings.Contains(string(b), `"new"`) {
		t.Errorf("after broken %s", b)
	}

	// Only the JSON left: no longer read (since 1.7), exit status 3, and
	// nothing rendered for it any more.
	if err := os.Remove(filepath.Join(src, "data.yaml")); err != nil {
		t.Fatal(err)
	}
	if rc, msg := render(); rc != exitJSON || !strings.Contains(msg, filepath.Join(src, "data.json")+": configuration in JSON is no longer read since 1.7: convert it to YAML with mcp-gateway-admin policy convert ") ||
		!strings.Contains(msg, "removed data.yaml") {
		t.Errorf("JSON: %d %s", rc, msg)
	}
	if rc, msg := render("-check"); rc != exitJSON || !strings.Contains(msg, out+" is current") {
		t.Errorf("check JSON: %d %s", rc, msg)
	}

	var stdout, stderr bytes.Buffer
	if rc := run(context.Background(), []string{"extra"}, &stdout, &stderr); rc != 2 {
		t.Errorf("usage: %d", rc)
	}
}

// syncBuffer is a bytes.Buffer safe for the watcher and the test.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// With -watch, every change below the role data's directory is rendered
// without a restart: subdirectories, files removed, the directory itself
// removed and created again, many writes in a row (the last one wins),
// and role data that does not parse is waited out. systemd hears ready
// once, after the first render.
func TestWatch(t *testing.T) {
	settle = 20 * time.Millisecond
	parent := t.TempDir()
	src, out := filepath.Join(parent, "rbac"), filepath.Join(t.TempDir(), "rbac")
	write := func(name, content string) {
		t.Helper()
		p := filepath.Join(src, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("data.json", `{"roles": {"a": {"permissions": []}}}`)
	var mu sync.Mutex
	var notified []string
	notify := func(s string) error { mu.Lock(); notified = append(notified, s); mu.Unlock(); return nil }
	var stderr syncBuffer
	r := renderer{src: src, out: out, shipped: "", say: func(f string, a ...any) { _, _ = fmt.Fprintf(&stderr, f+"\n", a...) }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int)
	go func() { done <- r.watch(ctx, notify) }()
	rendered := func(rel, want string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			b, err := os.ReadFile(filepath.Join(out, rel))
			got := strings.Join(strings.Fields(string(b)), "")
			if want == "" && os.IsNotExist(err) || want != "" && got == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: %q (%v), want %q\n%s", rel, got, err, want, stderr.String())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	// Role data in JSON is no longer read: nothing rendered.
	rendered("data.yaml", "")
	write("data.yaml", "roles: {b: {permissions: []}}\n")
	rendered("data.yaml", `{"roles":{"b":{"permissions":[]}}}`)
	write("managers/data.yaml", "alice: bob\n")
	rendered("managers/data.yaml", `{"alice":"bob"}`)
	if err := os.RemoveAll(filepath.Join(src, "managers")); err != nil {
		t.Fatal(err)
	}
	rendered("managers/data.yaml", "")
	// Back to the JSON alone: its rendering is gone, not the JSON's.
	if err := os.Remove(filepath.Join(src, "data.yaml")); err != nil {
		t.Fatal(err)
	}
	rendered("data.yaml", "")
	// Many writes in a row: the last one is in force.
	for i := 0; i < 20; i++ {
		write("data.yaml", fmt.Sprintf("roles: {r%d: {permissions: []}}\n", i))
	}
	rendered("data.yaml", `{"roles":{"r19":{"permissions":[]}}}`)
	// Not parsing: the rendering stays, and the next good one is taken.
	write("data.yaml", "roles: [\n")
	time.Sleep(100 * time.Millisecond)
	rendered("data.yaml", `{"roles":{"r19":{"permissions":[]}}}`)
	write("data.yaml", "roles: {fixed: {permissions: []}}\n")
	rendered("data.yaml", `{"roles":{"fixed":{"permissions":[]}}}`)
	// The directory removed and created again (watched in its parent).
	if err := os.RemoveAll(src); err != nil {
		t.Fatal(err)
	}
	rendered("data.yaml", "")
	write("data.yaml", "roles: {again: {permissions: []}}\n")
	rendered("data.yaml", `{"roles":{"again":{"permissions":[]}}}`)

	cancel()
	if rc := <-done; rc != 0 {
		t.Errorf("exit status %d", rc)
	}
	mu.Lock()
	defer mu.Unlock()
	ready := 0
	for _, n := range notified {
		if n == "READY=1" {
			ready++
		}
	}
	all := strings.Join(notified, "\n")
	if ready != 1 || !strings.Contains(all, "STATUS=role data not rendered") || !strings.Contains(all, "STATUS=role data in JSON left out") || notified[len(notified)-1] != "STOPPING=1" {
		t.Errorf("notified %q", notified)
	}
	if !strings.Contains(stderr.String(), "role data not rendered; the last rendering") {
		t.Errorf("stderr: %s", stderr.String())
	}
}

// With -watch, the shipped default is in force while the directory has
// no role data, and an update of it (a package update) is rendered too.
func TestWatchDefault(t *testing.T) {
	settle = 20 * time.Millisecond
	src, out := filepath.Join(t.TempDir(), "rbac"), filepath.Join(t.TempDir(), "rbac")
	def := filepath.Join(t.TempDir(), "data.yaml")
	if err := os.WriteFile(def, []byte("roles: {viewer: {permissions: []}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stderr syncBuffer
	r := renderer{src: src, out: out, def: def, say: func(f string, a ...any) { _, _ = fmt.Fprintf(&stderr, f+"\n", a...) }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int)
	go func() { done <- r.watch(ctx, func(string) error { return nil }) }()
	defer func() { cancel(); <-done }()
	rendered := func(want string) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			b, _ := os.ReadFile(filepath.Join(out, "data.yaml"))
			if got := strings.Join(strings.Fields(string(b)), ""); got == want {
				return
			} else if time.Now().After(deadline) {
				t.Fatalf("%q, want %q\n%s", got, want, stderr.String())
			}
		}
	}
	rendered(`{"roles":{"viewer":{"permissions":[]}}}`)
	// A package update replaces the default (a new file renamed over it).
	tmp := def + ".new"
	if err := os.WriteFile(tmp, []byte("roles: {viewer: {permissions: []}, auditor: {permissions: []}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, def); err != nil {
		t.Fatal(err)
	}
	rendered(`{"roles":{"viewer":{"permissions":[]},"auditor":{"permissions":[]}}}`)
	// The administrator's role data replaces it as a whole.
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "data.yaml"), []byte("roles: {mine: {permissions: []}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rendered(`{"roles":{"mine":{"permissions":[]}}}`)
}
