package config

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestKeys(t *testing.T) {
	keys := Keys()
	for _, want := range []string{"socket", "limits.tasks_per_principal", "approvals.url_template", "notifications.email.password_file", "agents.max_version"} {
		if !slices.Contains(keys, want) {
			t.Errorf("Keys lacks %s", want)
		}
	}
	for _, k := range keys {
		if _, section, err := KeyType(k); err != nil || section {
			t.Errorf("%s: section %v, %v", k, section, err)
		}
		if k == "limits" || k == "approvals" || strings.HasSuffix(k, ".email") {
			t.Errorf("section %s listed as a key", k)
		}
	}
}

func TestKeyType(t *testing.T) {
	if _, section, err := KeyType("limits"); err != nil || !section {
		t.Errorf("limits: section %v, %v", section, err)
	}
	for _, k := range []string{"nope", "limits.nope", "socket.x", "agents.max_version.kit", ""} {
		if _, _, err := KeyType(k); !errors.Is(err, ErrUnknownKey) {
			t.Errorf("%q: %v", k, err)
		}
	}
}

func TestValueAndSources(t *testing.T) {
	bases, dir := dropInSetup(t, "version: 1\nlimits:\n  sessions_per_principal: 10\nnotifications: ~\n")
	writeFile(t, dir, "50-a.yaml", "# a comment\nlimits:\n  tasks_per_principal: 7\napproval_timeout: 3m\n")
	g, used, err := ResolveWith(bases, dir)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := Value(g, "approval_timeout"); err != nil || v.Interface() != 3*time.Minute {
		t.Errorf("approval_timeout %v %v", v, err)
	}
	if _, err := Value(g, "limits.nope"); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("unknown key: %v", err)
	}
	src, err := Sources(used, g.DropIns)
	if err != nil {
		t.Fatal(err)
	}
	drop := g.DropIns[0]
	for key, want := range map[string]Source{
		"limits.sessions_per_principal": {used, 3},
		"limits.tasks_per_principal":    {drop, 3},
		"approval_timeout":              {drop, 4},
		// A section set to null: its keys come from there, at their defaults.
		"notifications.email.smtp": {used, 4},
	} {
		if src[key] != want {
			t.Errorf("%s: %+v, want %+v", key, src[key], want)
		}
	}
	if _, ok := src["socket"]; ok {
		t.Error("socket has a source; no file sets it")
	}
}

func TestResolveFiles(t *testing.T) {
	bases, dir := dropInSetup(t, "version: 1\nlimits:\n  sessions_per_principal: 10\n")
	p := writeFile(t, dir, "50-a.yaml", "limits:\n  tasks_per_principal: 7\n")
	g, err := ResolveFiles(bases[0], []string{p})
	if err != nil || g.Limits.TasksPerPrincipal != 7 || g.Limits.SessionsPerPrincipal != 10 {
		t.Fatalf("%v %+v", err, g)
	}
	if g, err = ResolveFiles("", nil); err != nil || g.Socket != DefaultSocket {
		t.Fatalf("defaults: %v %+v", err, g)
	}
}
