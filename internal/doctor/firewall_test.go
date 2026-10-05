package doctor

import (
	"errors"
	"strings"
	"testing"
)

// fakeFirewall answers firewall-cmd as firewalld with the given zones
// would; zones maps a zone to its --info-zone output.
func fakeFirewall(state string, active string, zones map[string]string) FirewallCmd {
	services := map[string]string{
		"ssh":        "ssh\n  ports: 22/tcp\n",
		"mcp-custom": "mcp-custom\n  ports: 8000-9000/tcp\n",
	}
	return func(args ...string) (string, error) {
		switch a := args[0]; {
		case a == "--state":
			if state != "running" {
				return state, errors.New("exit status 252")
			}
			return "running\n", nil
		case a == "--get-active-zones":
			return active, nil
		case a == "--get-default-zone":
			return "public\n", nil
		case strings.HasPrefix(a, "--info-zone="):
			if z, ok := zones[strings.TrimPrefix(a, "--info-zone=")]; ok {
				return z, nil
			}
			return "", errors.New("INVALID_ZONE")
		case strings.HasPrefix(a, "--info-service="):
			if s, ok := services[strings.TrimPrefix(a, "--info-service=")]; ok {
				return s, nil
			}
			return "", errors.New("INVALID_SERVICE")
		}
		return "", errors.New("unexpected " + strings.Join(args, " "))
	}
}

const (
	publicClosed = "public (active)\n  target: default\n  interfaces: eth0\n  services: dhcpv6-client ssh\n  ports: \n"
	publicOpen   = "public (active)\n  target: default\n  interfaces: eth0\n  services: ssh\n  ports: 8080/tcp 8443/tcp\n"
)

func TestFirewall(t *testing.T) {
	closed := fakeFirewall("running", "public\n  interfaces: eth0\n", map[string]string{"public": publicClosed})
	rs := Firewall(":8443", closed)
	if len(rs) != 1 || rs[0].Status != Warn ||
		!strings.Contains(rs[0].Summary, "8443/tcp") || !strings.Contains(rs[0].Summary, "connection refused") ||
		rs[0].Details[0] != "firewall-cmd --permanent --zone=public --add-port=8443/tcp && firewall-cmd --reload" {
		t.Fatalf("closed: %+v", rs)
	}
	if rs := Firewall(":8443", fakeFirewall("running", "public\n  interfaces: eth0\n", map[string]string{"public": publicOpen})); rs[0].Status != OK {
		t.Errorf("open: %+v", rs)
	}
	// Opened by a service's port range, or by an accepting zone.
	viaService := "internal (active)\n  target: default\n  services: mcp-custom\n  ports: \n"
	trusted := "trusted (active)\n  target: ACCEPT\n  services: \n  ports: \n"
	mixed := fakeFirewall("running", "internal\n  interfaces: eth1\npublic\n  interfaces: eth0\ntrusted\n  sources: 10.0.0.0/8\n",
		map[string]string{"internal": viaService, "public": publicClosed, "trusted": trusted})
	rs = Firewall("0.0.0.0:8443", mixed)
	if rs[0].Status != OK || !strings.Contains(rs[0].Summary, "internal, trusted") || !strings.Contains(rs[0].Details[0], "public") {
		t.Errorf("mixed: %+v", rs)
	}
	// No active zone: the default zone.
	if rs := Firewall(":8443", fakeFirewall("running", "", map[string]string{"public": publicClosed})); rs[0].Status != Warn ||
		!strings.Contains(rs[0].Summary, "(public)") {
		t.Errorf("default zone: %+v", rs)
	}
	// Nothing to check: no listener, loopback, firewalld not running.
	for _, c := range []struct {
		listen string
		run    FirewallCmd
	}{{"", closed}, {"127.0.0.1:8443", closed}, {"localhost:8443", closed}, {"[::1]:8443", closed},
		{":8443", fakeFirewall("not running", "", nil)}} {
		if rs := Firewall(c.listen, c.run); len(rs) != 0 {
			t.Errorf("%q: %+v", c.listen, rs)
		}
	}
}

func TestPortsInclude(t *testing.T) {
	for _, c := range []struct {
		list string
		want bool
	}{{"8443/tcp", true}, {"22/tcp 8443/tcp", true}, {"8000-9000/tcp", true}, {"8443/udp", false},
		{"84430/tcp", false}, {"", false}, {"9000-9100/tcp", false}} {
		if got := portsInclude(c.list, "8443"); got != c.want {
			t.Errorf("%q: %v", c.list, got)
		}
	}
}
