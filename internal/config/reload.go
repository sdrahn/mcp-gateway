package config

import (
	"reflect"
	"strings"
)

// Reloadable are the keys of gateway.yaml a running gateway applies when
// its configuration is reloaded (docs/architecture.md, roadmap step 19):
// a key, or every key below a section. The others take effect at the
// next start.
var Reloadable = []string{
	"approval_timeout",
	"approvals.url_template",
	"approvals.progress_interval",
	"notifications",
	"limits",
	"supervisor.idle_timeout",
	"policy.timeout",
	"policy.watch_interval",
	"http.cert_file",
	"http.key_file",
	"http.list_ttl",
}

// RestartNeeded returns the keys whose value in next differs from
// running and that a reload does not apply, sorted ("http.listen",
// "socket_group", …).
func RestartNeeded(running, next *Gateway) []string {
	var all []string
	diffAll(reflect.ValueOf(*running), reflect.ValueOf(*next), "", &all)
	var out []string
	for _, k := range all {
		if !reloadable(k) && k != "version" {
			out = append(out, k)
		}
	}
	return out
}

func reloadable(key string) bool {
	for _, k := range Reloadable {
		if key == k || strings.HasPrefix(key, k+".") {
			return true
		}
	}
	return false
}

// Changed returns the reloadable keys whose value in next differs from
// running: what a reload changes.
func Changed(running, next *Gateway) []string {
	var all []string
	diffAll(reflect.ValueOf(*running), reflect.ValueOf(*next), "", &all)
	var out []string
	for _, k := range all {
		if reloadable(k) {
			out = append(out, k)
		}
	}
	return out
}

// diffAll is diffKeys without leaving out the reloadable keys.
func diffAll(a, b reflect.Value, prefix string, out *[]string) {
	t := a.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if !f.IsExported() || name == "" || name == "-" {
			continue
		}
		key := name
		if prefix != "" {
			key = prefix + "." + name
		}
		x, y := a.Field(i), b.Field(i)
		if f.Type.Kind() == reflect.Struct && f.Type.PkgPath() == t.PkgPath() {
			diffAll(x, y, key, out)
			continue
		}
		if !reflect.DeepEqual(x.Interface(), y.Interface()) {
			*out = append(*out, key)
		}
	}
}
