package supervisor

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"slices"
	"time"

	sddbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/egress"
)

// lookupTimeout bounds resolving the host of a server defined with url.
const lookupTimeout = 10 * time.Second

// ipAddress is an entry of IPAddressAllow= and IPAddressDeny= (D-Bus
// a(iayu): family, address bytes, prefix length).
type ipAddress struct {
	Family    int32
	Address   []byte
	PrefixLen uint32
}

func ipEntry(ip net.IP, prefix int) ipAddress {
	if v4 := ip.To4(); v4 != nil {
		return ipAddress{Family: 2, Address: v4, PrefixLen: uint32(min(prefix, 32))}
	}
	return ipAddress{Family: 10, Address: ip.To16(), PrefixLen: uint32(prefix)}
}

// httpTarget resolves the host of a server defined with url (b.URL), or
// of its proxy (b.Proxy), which then resolves the server's name, with
// lookup (net.DefaultResolver.LookupIP outside tests). The connector gets
// the addresses (-resolve host:port:address), since its domain cannot
// resolve names, and the unit may reach those only. With b.PublicOnly,
// an address of the local network is an error (through a proxy, which
// resolves the name itself, only an address in the URL can be checked).
func httpTarget(ctx context.Context, b *config.Backend, lookup func(ctx context.Context, network, host string) ([]net.IP, error)) (args []string, allow []ipAddress, err error) {
	if b.PublicOnly {
		if err := checkPublic(b); err != nil {
			return nil, nil, err
		}
	}
	target := b.URL
	if b.Proxy != "" {
		target = b.Proxy
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, nil, err
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	ips := []net.IP{net.ParseIP(host)}
	if ips[0] == nil {
		ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
		defer cancel()
		if ips, err = lookup(ctx, "ip", host); err != nil {
			return nil, nil, fmt.Errorf("supervisor: resolving %s for server %s: %w", host, b.Name, err)
		}
	}
	if b.PublicOnly && b.Proxy == "" {
		for _, ip := range ips {
			if !egress.Public(ip) {
				return nil, nil, localAddress(b, host, ip)
			}
		}
	}
	slices.SortFunc(ips, func(a, b net.IP) int { return slices.Compare(a.To16(), b.To16()) })
	for _, ip := range slices.CompactFunc(ips, net.IP.Equal) {
		args = append(args, "-resolve", net.JoinHostPort(host, port)+":"+ip.String())
		allow = append(allow, ipEntry(ip, 128))
	}
	if len(allow) == 0 {
		return nil, nil, fmt.Errorf("supervisor: %s for server %s has no address", host, b.Name)
	}
	return args, allow, nil
}

// httpProperties limit the unit's network to allow.
func httpProperties(allow []ipAddress) []sddbus.Property {
	deny := []ipAddress{ipEntry(net.IPv4zero, 0), ipEntry(net.IPv6zero, 0)}
	return []sddbus.Property{
		{Name: "IPAddressDeny", Value: dbus.MakeVariant(deny)},
		{Name: "IPAddressAllow", Value: dbus.MakeVariant(allow)},
	}
}

// checkPublic refuses a URL whose host is an address of the local
// network.
func checkPublic(b *config.Backend) error {
	u, err := url.Parse(b.URL)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !egress.Public(ip) {
		return localAddress(b, u.Hostname(), ip)
	}
	return nil
}

func localAddress(b *config.Backend, host string, ip net.IP) error {
	return fmt.Errorf("supervisor: %s for %s is %s, an address of the local network, which a server's metadata may not send the sign-in helper to; list the host in sign_in.private_hosts if the authorization server is there",
		host, b.Name, ip)
}
