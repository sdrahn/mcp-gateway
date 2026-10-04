package supervisor

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

func TestHTTPTarget(t *testing.T) {
	lookup := func(_ context.Context, _, host string) ([]net.IP, error) {
		if host != "mcp.example.com" {
			return nil, errors.New("no such host")
		}
		return []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.7"), net.ParseIP("192.0.2.7")}, nil
	}
	b := &config.Backend{Name: "remote", URL: "https://mcp.example.com/mcp"}
	args, allow, err := httpTarget(context.Background(), b, lookup)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-resolve", "mcp.example.com:443:192.0.2.7", "-resolve", "mcp.example.com:443:2001:db8::1"}
	if !slices.Equal(args, want) {
		t.Errorf("args %v", args)
	}
	if len(allow) != 2 || allow[0].Family != 2 || len(allow[0].Address) != 4 || allow[0].PrefixLen != 32 ||
		allow[1].Family != 10 || len(allow[1].Address) != 16 || allow[1].PrefixLen != 128 {
		t.Errorf("allow %+v", allow)
	}

	// An address in the URL is used as it is; the port is the URL's.
	b.URL = "http://127.0.0.1:8008/mcp"
	if args, _, err := httpTarget(context.Background(), b, nil); err != nil || !slices.Equal(args, []string{"-resolve", "127.0.0.1:8008:127.0.0.1"}) {
		t.Errorf("literal: %v %v", args, err)
	}

	b.URL = "https://unknown.example.com/"
	if _, _, err := httpTarget(context.Background(), b, lookup); err == nil || !strings.Contains(err.Error(), "resolving unknown.example.com for server remote") {
		t.Errorf("unknown host: %v", err)
	}

	props := httpProperties(allow)
	if len(props) != 2 || props[0].Name != "IPAddressDeny" || props[1].Name != "IPAddressAllow" {
		t.Errorf("props %+v", props)
	}
}
