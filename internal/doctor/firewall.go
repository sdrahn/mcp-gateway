package doctor

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// FirewallCmd runs firewall-cmd with args and returns its output.
type FirewallCmd func(args ...string) (string, error)

// Firewall checks that firewalld lets remote clients reach the HTTP
// listener (listen, http.listen): a port no active zone opens is rejected,
// which clients report as "connection refused" while everything works on
// the host itself. A zone opens the port with its ports, with one of its
// services, or by accepting everything (target ACCEPT). It returns
// nothing without the listener, for a listener on loopback, and when
// firewalld does not run (firewall-cmd missing or not running).
func Firewall(listen string, run FirewallCmd) []Result {
	if listen == "" {
		return nil
	}
	port, loopback := listenPort(listen)
	if port == "" || loopback {
		return nil
	}
	if out, err := run("--state"); err != nil || strings.TrimSpace(out) != "running" {
		return nil
	}
	r := Result{Check: "firewall"}
	zones, err := activeZones(run)
	if err != nil {
		r.Status, r.Summary = Skip, "firewall-cmd: "+err.Error()
		return []Result{r}
	}
	want := port + "/tcp"
	var open, closed []string
	for _, z := range zones {
		ok, err := zoneOpens(run, z, port)
		if err != nil {
			r.Status, r.Summary = Skip, "firewall-cmd: "+err.Error()
			return []Result{r}
		}
		if ok {
			open = append(open, z)
		} else {
			closed = append(closed, z)
		}
	}
	if len(open) == 0 {
		r.Status = Warn
		r.Summary = fmt.Sprintf("firewalld opens %s (http.listen) in no active zone (%s): remote clients get \"connection refused\"",
			want, strings.Join(zones, ", "))
		for _, z := range zones {
			r.Details = append(r.Details, fmt.Sprintf("firewall-cmd --permanent --zone=%s --add-port=%s && firewall-cmd --reload", z, want))
		}
		return []Result{r}
	}
	r.Status, r.Summary = OK, fmt.Sprintf("firewalld opens %s in zone %s", want, strings.Join(open, ", "))
	if len(closed) > 0 {
		r.Details = []string{"not in zone " + strings.Join(closed, ", ") + ": clients there are refused"}
	}
	return []Result{r}
}

// activeZones returns the zones with an interface or source; with none,
// the default zone, which then applies to every interface.
func activeZones(run FirewallCmd) ([]string, error) {
	out, err := run("--get-active-zones")
	var zones []string
	if err == nil {
		for _, line := range strings.Split(out, "\n") {
			if line != "" && line[0] != ' ' && line[0] != '\t' {
				zones = append(zones, strings.Fields(line)[0])
			}
		}
	}
	if len(zones) > 0 {
		return zones, nil
	}
	out, err = run("--get-default-zone")
	if err != nil {
		return nil, err
	}
	return []string{strings.TrimSpace(out)}, nil
}

// zoneOpens reports whether zone lets TCP connections to port in.
func zoneOpens(run FirewallCmd, zone, port string) (bool, error) {
	out, err := run("--info-zone=" + zone)
	if err != nil {
		return false, err
	}
	info := fields(out)
	if t := info["target"]; t == "ACCEPT" || t == "%%ACCEPT%%" {
		return true, nil
	}
	if portsInclude(info["ports"], port) {
		return true, nil
	}
	for _, s := range strings.Fields(info["services"]) {
		out, err := run("--info-service=" + s)
		if err != nil {
			continue // an unknown service opens nothing
		}
		if portsInclude(fields(out)["ports"], port) {
			return true, nil
		}
	}
	return false, nil
}

// fields parses firewall-cmd's "  key: value" lines.
func fields(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

// portsInclude reports whether a ports list ("8443/tcp 9000-9100/tcp")
// includes port over TCP.
func portsInclude(list, port string) bool {
	p, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(strings.Fields(list), func(e string) bool {
		spec, proto, _ := strings.Cut(e, "/")
		if proto != "tcp" {
			return false
		}
		lo, hi, isRange := strings.Cut(spec, "-")
		a, err1 := strconv.Atoi(lo)
		b := a
		var err2 error
		if isRange {
			b, err2 = strconv.Atoi(hi)
		}
		return err1 == nil && err2 == nil && a <= p && p <= b
	})
}
