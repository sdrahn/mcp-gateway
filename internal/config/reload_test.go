package config

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRestartNeeded(t *testing.T) {
	running := &Gateway{}
	running.setDefaults()
	next := *running
	if got := RestartNeeded(running, &next); len(got) != 0 {
		t.Fatalf("same configuration: %v", got)
	}
	// Reloadable keys do not count.
	next.ApprovalTimeout = time.Minute
	next.Limits.Instances = 10
	next.Notifications.Email.SMTP = "localhost:25"
	next.Supervisor.IdleTimeout = time.Hour
	next.Policy.Timeout = time.Second
	next.HTTP.CertFile = "/etc/new.pem"
	if got := RestartNeeded(running, &next); len(got) != 0 {
		t.Fatalf("reloadable keys: %v", got)
	}
	next.SocketGroup = "other"
	next.HTTP.Listen = ":8443"
	next.HTTP.Scopes = []string{"mcp"}
	next.Supervisor.MCSRange = "c0.c100"
	next.Policy.OPASocket = "/run/x.sock"
	want := []string{"socket_group", "http.listen", "http.scopes", "policy.opa_socket", "supervisor.mcs_range"}
	got := RestartNeeded(running, &next)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// Every reloadable key names a key or section of the configuration.
func TestReloadableKeysExist(t *testing.T) {
	var keys []string
	var walk func(rt reflect.Type, prefix string)
	walk = func(rt reflect.Type, prefix string) {
		for i := range rt.NumField() {
			f := rt.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if name == "" || name == "-" {
				continue
			}
			key := strings.TrimPrefix(prefix+"."+name, ".")
			keys = append(keys, key)
			if f.Type.Kind() == reflect.Struct && f.Type.PkgPath() == rt.PkgPath() {
				walk(f.Type, key)
			}
		}
	}
	walk(reflect.TypeFor[Gateway](), "")
	for _, k := range Reloadable {
		if !slices.Contains(keys, k) {
			t.Errorf("%q is not a key of gateway.yaml", k)
		}
	}
}
