package egress

import (
	"net"
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

func TestPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"8.8.8.8": true, "2a00:1450:4001::200e": true, "192.0.2.7": true,
		"10.1.2.3": false, "172.16.0.1": false, "192.168.1.1": false, "127.0.0.1": false, "::1": false,
		"169.254.169.254": false, "fe80::1": false, "fd00::1": false, "0.0.0.0": false, "::": false,
		"100.64.0.1": false, "224.0.0.1": false, "ff02::1": false, "255.255.255.255": false, "198.18.0.1": false,
		"::ffff:10.0.0.1": false, "64:ff9b::a00:1": false, "64:ff9b::808:808": true,
	} {
		if got := Public(net.ParseIP(addr)); got != want {
			t.Errorf("%s: %v, want %v", addr, got, want)
		}
	}
	if Public(nil) {
		t.Error("nil")
	}
}
