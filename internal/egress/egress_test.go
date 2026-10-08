package egress

import (
	"net/url"
	"slices"
	"testing"
)

// The ports a connecting program may reach: the proxy's when it
// tunnels, else the server's and those resolved; none known, TCP alone.
func TestLandlock(t *testing.T) {
	mustURL := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	for _, c := range []struct {
		o      Options
		target string
		want   []int
	}{
		{Options{}, "https://mcp.example.com/mcp", []int{53, 443}},
		{Options{}, "http://127.0.0.1:8080/mcp", []int{53, 8080}},
		{Options{Resolve: []string{"auth.example.com:8443:192.0.2.1"}}, "", []int{53, 8443}},
		{Options{Proxy: mustURL("http://proxy:3128"), Resolve: []string{"x:443:192.0.2.1"}}, "https://x/mcp", []int{53, 3128}},
		{Options{}, "", nil},
	} {
		var target *url.URL
		if c.target != "" {
			target = mustURL(c.target)
		}
		r := Landlock(c.o, target, "/run/credentials/mcp-x.service")
		if !slices.Equal(r.TCPConnect, c.want) {
			t.Errorf("%+v %s: tcp_connect %v, want %v", c.o, c.target, r.TCPConnect, c.want)
		}
		if !slices.Contains(r.Read, "/run/credentials/mcp-x.service") || !slices.Contains(r.Read, "/var/lib/ca-certificates") {
			t.Errorf("read %v", r.Read)
		}
	}
}
