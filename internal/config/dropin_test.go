package config

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// dropInSetup returns a base gateway.yaml with content (none for "") and
// an empty gateway.d next to it.
func dropInSetup(t *testing.T, content string) (bases []string, dir string) {
	t.Helper()
	root := t.TempDir()
	dir = filepath.Join(root, "gateway.d")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, "gateway.yaml")
	if content != "" {
		writeFile(t, root, "gateway.yaml", content)
	}
	return []string{base}, dir
}

const dropInBase = `version: 1
approval_timeout: 90s
approvals:
  url_template: https://h/approve/{id}
  retry_wait: 5s
limits:
  sessions_per_principal: 10
  tasks_per_principal: 32
agents:
  max_version:
    kit: "2025-11-25"
    other: "2025-06-18"
  no_request_timeout: [kit, other]
`

func TestDropInsMerge(t *testing.T) {
	bases, dir := dropInSetup(t, dropInBase)
	writeFile(t, dir, "20-limits.yaml", "limits:\n  tasks_per_principal: 64\n")
	writeFile(t, dir, "30-later.yaml", "version: 1\nlimits:\n  tasks_per_principal: 128\napprovals:\n  retry_wait: 7s\n")
	writeFile(t, dir, "40-agents.yaml", "agents:\n  max_version: {}\n  no_request_timeout: [kit]\n")
	// Not drop-ins: hidden, another suffix, a directory.
	writeFile(t, dir, ".50-tmp.yaml", "limits: {tasks_per_principal: 1}\n")
	writeFile(t, dir, "60-notes.yaml.bak", "nonsense: true\n")
	if err := os.Mkdir(filepath.Join(dir, "70-dir.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	g, used, err := ResolveWith(bases, dir)
	if err != nil {
		t.Fatal(err)
	}
	if used != bases[0] {
		t.Errorf("used %q", used)
	}
	if want := []string{filepath.Join(dir, "20-limits.yaml"), filepath.Join(dir, "30-later.yaml"), filepath.Join(dir, "40-agents.yaml")}; !slices.Equal(g.DropIns, want) {
		t.Errorf("drop-ins %v, want %v", g.DropIns, want)
	}
	// The later drop-in wins; a section merges, keeping the base's keys.
	if g.Limits.TasksPerPrincipal != 128 || g.Limits.SessionsPerPrincipal != 10 {
		t.Errorf("limits %+v", g.Limits)
	}
	if g.Approvals.RetryWait != 7*time.Second || g.Approvals.URLTemplate != "https://h/approve/{id}" || g.ApprovalTimeout != 90*time.Second {
		t.Errorf("approvals %+v, approval_timeout %v", g.Approvals, g.ApprovalTimeout)
	}
	// A map of names and a list replace.
	if len(g.Agents.MaxVersion) != 0 {
		t.Errorf("max_version %v, want {} (replaced)", g.Agents.MaxVersion)
	}
	if !slices.Equal(g.Agents.NoRequestTimeout, []string{"kit"}) {
		t.Errorf("no_request_timeout %v", g.Agents.NoRequestTimeout)
	}
}

func TestDropInsOverDefaults(t *testing.T) {
	bases, dir := dropInSetup(t, "")
	writeFile(t, dir, "50-admin.yaml", "limits:\n  tasks_per_principal: 7\n")
	g, used, err := ResolveWith(bases, dir)
	if err != nil {
		t.Fatal(err)
	}
	if used != "" || g.Limits.TasksPerPrincipal != 7 || g.Socket != DefaultSocket {
		t.Errorf("used %q, tasks %d, socket %q", used, g.Limits.TasksPerPrincipal, g.Socket)
	}
	// An empty drop-in changes nothing.
	writeFile(t, dir, "60-empty.yaml", "")
	if g, _, err = ResolveWith(bases, dir); err != nil || g.Limits.TasksPerPrincipal != 7 {
		t.Fatalf("with an empty drop-in: %v, %+v", err, g)
	}
}

func TestDropInsNone(t *testing.T) {
	bases, dir := dropInSetup(t, dropInBase)
	g, _, err := ResolveWith(bases, filepath.Join(dir, "missing"))
	if err != nil {
		t.Fatal(err)
	}
	if g.Limits.TasksPerPrincipal != 32 || g.DropIns != nil {
		t.Errorf("tasks %d, drop-ins %v", g.Limits.TasksPerPrincipal, g.DropIns)
	}
}

// An explicit configuration reads no drop-ins.
func TestDropInsNotWithExplicit(t *testing.T) {
	bases, dir := dropInSetup(t, dropInBase)
	writeFile(t, dir, "50-admin.yaml", "limits:\n  tasks_per_principal: 7\n")
	g, used, err := Resolve(bases[0])
	if err != nil {
		t.Fatal(err)
	}
	if used != bases[0] || g.Limits.TasksPerPrincipal != 32 || g.DropIns != nil {
		t.Errorf("used %q, tasks %d, drop-ins %v", used, g.Limits.TasksPerPrincipal, g.DropIns)
	}
}

func TestDropInsErrors(t *testing.T) {
	for _, tc := range []struct{ name, content, want string }{
		{"unknown key", "limits:\n  task_per_principal: 7\n", "field task_per_principal not found"},
		{"wrong type", "limits:\n  tasks_per_principal: many\n", "line 2"},
		{"not a mapping", "- a\n- b\n", "not a mapping of keys"},
		{"newer version", "version: 99\n", "version: 99 is newer"},
		{"invalid as a whole", "policy:\n  timeout: -1s\n", "policy.timeout: must not be negative"},
		{"syntax", "limits: [\n", "did not find expected"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bases, dir := dropInSetup(t, dropInBase)
			writeFile(t, dir, "10-good.yaml", "limits:\n  tasks_per_principal: 64\n")
			bad := writeFile(t, dir, "50-bad.yaml", tc.content)
			_, _, err := ResolveWith(bases, dir)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), bad) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q, want the file and %q", err, tc.want)
			}
			var fe *FileError
			if !errors.As(err, &fe) || fe.Path != bad {
				t.Errorf("file error %+v", fe)
			}
			if got := ErrorFile(err); got != "gateway.d/50-bad.yaml" {
				t.Errorf("ErrorFile %q", got)
			}
		})
	}
}

// An error in the base file names it, before any drop-in is read.
func TestDropInsBaseError(t *testing.T) {
	bases, dir := dropInSetup(t, "nonsense: 1\n")
	writeFile(t, dir, "50-admin.yaml", "limits:\n  tasks_per_principal: 7\n")
	_, _, err := ResolveWith(bases, dir)
	var fe *FileError
	if !errors.As(err, &fe) || fe.Path != bases[0] || ErrorFile(err) != "gateway.yaml" {
		t.Fatalf("error %v (%+v)", err, fe)
	}
}

// A drop-in's deprecated keys warn with its name.
func TestDropInsWarnings(t *testing.T) {
	saved := gatewayDeprecations
	t.Cleanup(func() { gatewayDeprecations = saved })
	gatewayDeprecations = []deprecation{{Key: "limits.tasks_per_principal", Since: "9.9", Use: "something else"}}
	bases, dir := dropInSetup(t, "version: 1\n")
	p := writeFile(t, dir, "50-admin.yaml", "limits:\n  tasks_per_principal: 7\n")
	g, _, err := ResolveWith(bases, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Warnings) != 1 || !strings.HasPrefix(g.Warnings[0], p+": limits.tasks_per_principal is deprecated") {
		t.Errorf("warnings %q", g.Warnings)
	}
}

func TestErrorFileDefault(t *testing.T) {
	if got := ErrorFile(errors.New("x")); got != "gateway.yaml" {
		t.Errorf("ErrorFile %q", got)
	}
}

// Drop-ins that set nothing leave the configuration below as it is.
func TestDropInsOnlyEmpty(t *testing.T) {
	for _, content := range []string{dropInBase, ""} {
		bases, dir := dropInSetup(t, content)
		writeFile(t, dir, "50-empty.yaml", "# nothing yet\n")
		g, _, err := ResolveWith(bases, dir)
		if err != nil {
			t.Fatal(err)
		}
		want := DefaultSessionsPerPrincipal
		if content != "" {
			want = 10
		}
		if g.Limits.SessionsPerPrincipal != want || len(g.DropIns) != 1 {
			t.Errorf("sessions %d (want %d), drop-ins %v", g.Limits.SessionsPerPrincipal, want, g.DropIns)
		}
	}
}
