package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadGatewayDefaults(t *testing.T) {
	p := writeFile(t, t.TempDir(), "gateway.yaml", "{}\n")
	g, err := LoadGateway(p)
	if err != nil {
		t.Fatal(err)
	}
	if g.Socket != DefaultSocket || g.Policy.OPASocket != DefaultOPASocket || g.Policy.Timeout != DefaultPolicyTimeout ||
		g.Supervisor.Mode != "systemd" || g.Supervisor.SELinux != "auto" || g.ApprovalTimeout != DefaultApprovalTimeout ||
		g.Supervisor.IdleTimeout != DefaultIdleTimeout ||
		g.Approvals.ControlSocket != DefaultControl || g.Policy.WatchInterval != DefaultWatchInterval ||
		g.Limits.SessionsPerPrincipal != DefaultSessionsPerPrincipal || g.Limits.InstancesPerPrincipal != DefaultInstancesPerPrincipal ||
		g.Limits.Instances != 0 {
		t.Errorf("defaults not applied: %+v", g)
	}
}

func TestLoadGatewayShippedExample(t *testing.T) {
	g, err := LoadGateway("../../config/gateway.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if g.Policy.Timeout != 250*time.Millisecond {
		t.Errorf("policy.timeout = %v", g.Policy.Timeout)
	}
}

func TestLoadGatewayHTTP(t *testing.T) {
	p := writeFile(t, t.TempDir(), "gateway.yaml", `http:
  listen: ":8443"
  cert_file: c
  key_file: k
  issuer: http://127.0.0.1:9000/realms/mcp
  audience: https://gw.example.com:8443/mcp
  scopes: [mcp]
`)
	g, err := LoadGateway(p)
	if err != nil {
		t.Fatal(err)
	}
	if g.HTTP.GroupsClaim != "groups" || g.HTTP.SessionIdleTimeout != DefaultHTTPSessionIdle || g.HTTP.Scopes[0] != "mcp" {
		t.Errorf("http = %+v", g.HTTP)
	}
}

func TestLoadGatewayErrors(t *testing.T) {
	tests := map[string]string{
		"unknown field":    "sockett: /run/x.sock\n",
		"relative socket":  "socket: mcp.sock\n",
		"http no tls":      "http:\n  listen: ':8443'\n  issuer: x\n  audience: y\n",
		"http no issuer":   "http:\n  listen: ':8443'\n  cert_file: c\n  key_file: k\n",
		"mtls no ca":       "http:\n  listen: ':8443'\n  cert_file: c\n  key_file: k\n  issuer: x\n  audience: y\n  client_auth: required\n",
		"bound no mtls":    "http:\n  listen: ':8443'\n  cert_file: c\n  key_file: k\n  issuer: x\n  audience: y\n  require_bound_tokens: true\n",
		"bad client auth":  "http:\n  listen: ':8443'\n  cert_file: c\n  key_file: k\n  issuer: x\n  audience: y\n  client_auth: maybe\n  client_ca_file: ca.pem\n",
		"bad mode":         "supervisor:\n  mode: docker\n",
		"fast watch":       "policy:\n  watch_interval: 10ms\n",
		"bad audit":        "audit:\n  kernel: maybe\n",
		"bad mcs range":    "supervisor:\n  mcs_range: c10-c20\n",
		"mcs out of range": "supervisor:\n  mcs_range: c1000.c1100\n",
		"mcs too small":    "supervisor:\n  mcs_range: c1.c4\n",
		"bad mcs avoid":    "supervisor:\n  mcs_avoid: maybe\n",
		"smtp no port":     "notifications:\n  email:\n    smtp: mail\n    from: gw@x\n",
		"smtp no from":     "notifications:\n  email:\n    smtp: mail:25\n",
		"bad starttls":     "notifications:\n  email:\n    smtp: mail:25\n    from: gw@x\n    starttls: maybe\n",
		"user no pass":     "notifications:\n  email:\n    smtp: mail:25\n    from: gw@x\n    username: gw\n",
		"url no id":        "approvals:\n  url_template: https://h/approve\n",
		"url plain":        "approvals:\n  url_template: http://h.example.com/{id}\n",
		"relative ctl":     "approvals:\n  control_socket: ctl.sock\n",
		"http issuer url":  "http:\n  listen: ':8443'\n  cert_file: c\n  key_file: k\n  issuer: idp\n  audience: https://gw/mcp\n",
		"http plain aud":   "http:\n  listen: ':8443'\n  cert_file: c\n  key_file: k\n  issuer: https://idp\n  audience: http://gw.example.com/mcp\n",
		"bad selinux":      "supervisor:\n  selinux: maybe\n",
		"negative limit":   "limits:\n  instances: -1\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			p := writeFile(t, t.TempDir(), "gateway.yaml", content)
			if _, err := LoadGateway(p); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestLoadBackendsShippedExamples(t *testing.T) {
	bs, err := LoadBackends("../../config/servers.d")
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) == 0 {
		t.Fatal("no backends loaded")
	}
	for name, b := range bs {
		if b.Name != name {
			t.Errorf("key %q != name %q", name, b.Name)
		}
	}
}

func TestLoadBackendsDefaults(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", "name: a\ncommand: [/usr/bin/a]\n")
	bs, err := LoadBackends(dir)
	if err != nil {
		t.Fatal(err)
	}
	b := bs["a"]
	if b.SELinuxType != DefaultSELinuxType || b.Isolation != IsolationPrincipal ||
		b.RunAs != DefaultRunAs || b.Sandbox.ProtectHome != DefaultProtectHome || b.Network {
		t.Errorf("defaults not applied: %+v", b)
	}
}

// A definition starting a command a release removed is reported as one
// that cannot start.
func TestLoadBackendsRemovedCommand(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "old.yaml", "name: old\ncommand: [/usr/bin/mcp-gateway, admin-server]\n")
	writeFile(t, dir, "new.yaml", "name: new\ncommand: [/usr/bin/mcp-gateway-admin, serve]\n")
	writeFile(t, dir, "gw.yaml", "name: gw\ncommand: [/usr/bin/mcp-gateway]\n")
	bs, err := LoadBackends(dir)
	if err != nil {
		t.Fatal(err)
	}
	if w := bs["old"].Warnings; len(w) != 1 || !strings.Contains(w[0], "mcp-gateway admin-server was removed in 0.8, so this server cannot start") ||
		!strings.Contains(w[0], "mcp-gateway-admin serve") {
		t.Errorf("old: %q", w)
	}
	for _, name := range []string{"new", "gw"} {
		if w := bs[name].Warnings; len(w) != 0 {
			t.Errorf("%s: %q", name, w)
		}
	}
}

func TestLoadBackendsVendorOverrideMask(t *testing.T) {
	vendor, admin := t.TempDir(), t.TempDir()
	writeFile(t, vendor, "fs.yaml", "name: fs\ncommand: [/usr/libexec/mcp-servers/fs]\n")
	writeFile(t, vendor, "git.yaml", "name: git\ncommand: [/usr/libexec/mcp-servers/git]\n")
	writeFile(t, vendor, "db.yaml", "name: db\ncommand: [/usr/libexec/mcp-servers/db]\n")
	// Override fs, mask git (empty file) and db (symlink to /dev/null), add local.
	writeFile(t, admin, "fs.yaml", "name: fs\ncommand: [/opt/fs]\nnetwork: true\n")
	writeFile(t, admin, "git.yaml", "")
	if err := os.Symlink("/dev/null", filepath.Join(admin, "db.yaml")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, admin, "local.yaml", "name: local\ncommand: [/usr/local/bin/local]\n")

	bs, err := LoadBackends(vendor, admin, filepath.Join(admin, "missing"))
	if err != nil {
		t.Fatal(err)
	}
	if len(bs) != 2 || bs["fs"] == nil || bs["local"] == nil {
		t.Fatalf("backends %v", bs)
	}
	if bs["fs"].Command[0] != "/opt/fs" || !bs["fs"].Network {
		t.Errorf("fs not overridden: %+v", bs["fs"])
	}
}

func TestParseCredentials(t *testing.T) {
	b := &Backend{Credentials: []string{"github-token", "db:/srv/secrets/db.pass"}}
	cs, err := b.ParseCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 2 || cs[0] != (Credential{"github-token", DefaultCredentialsDir + "/github-token"}) ||
		cs[1] != (Credential{"db", "/srv/secrets/db.pass"}) {
		t.Fatalf("credentials %+v", cs)
	}
}

func TestResolveExplicitMissing(t *testing.T) {
	if _, _, err := Resolve(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for a missing explicit config")
	}
}

func TestLoadBackendsSandbox(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", "name: a\ncommand: [/usr/bin/a]\nsandbox:\n"+
		"  read_write_paths: [/var/lib/a, /srv/data]\n  state_directory: a/cache\n")
	reg, err := LoadBackends(dir)
	if err != nil {
		t.Fatal(err)
	}
	sb := reg["a"].Sandbox
	if len(sb.ReadWritePaths) != 2 || sb.ReadWritePaths[1] != "/srv/data" || sb.StateDirectory != "a/cache" {
		t.Errorf("sandbox %+v", sb)
	}
}

func TestLoadBackendsPrivileged(t *testing.T) {
	vendor, admin := t.TempDir(), t.TempDir()
	const def = "name: zypp\ncommand: [/usr/bin/mcp-server-zypp]\nrun_as: root\nprivileged: true\n"
	writeFile(t, admin, "zypp.yaml", def)
	bs, err := LoadBackends(vendor, admin)
	if err != nil {
		t.Fatal(err)
	}
	if !bs["zypp"].Privileged {
		t.Errorf("not privileged: %+v", bs["zypp"])
	}
	// A package (vendor dir) cannot define one, not even when the
	// administrator's directory is missing.
	writeFile(t, vendor, "other.yaml", strings.Replace(def, "zypp", "other", 1))
	for _, dirs := range [][]string{{vendor, admin}, {vendor, filepath.Join(admin, "missing")}} {
		if _, err := LoadBackends(dirs...); err == nil || !strings.Contains(err.Error(), "privileged: only allowed in") {
			t.Errorf("%v: err = %v", dirs, err)
		}
	}
}

func TestLoadBackendsErrors(t *testing.T) {
	tests := map[string][]string{
		"bad name":         {"name: Bad_Name\ncommand: [/usr/bin/a]\n"},
		"relative command": {"name: a\ncommand: [a]\n"},
		"empty command":    {"name: a\n"},
		"bad selinux type": {"name: a\ncommand: [/usr/bin/a]\nselinux_type: unconfined_t\n"},
		"bad isolation":    {"name: a\ncommand: [/usr/bin/a]\nisolation: global\n"},
		"bad discovery":    {"name: a\ncommand: [/usr/bin/a]\ndiscovery: cached\n"},
		"bad protect_home": {"name: a\ncommand: [/usr/bin/a]\nsandbox:\n  protect_home: maybe\n"},
		"bad cred name":    {"name: a\ncommand: [/usr/bin/a]\ncredentials: [\"../x\"]\n"},
		"relative cred":    {"name: a\ncommand: [/usr/bin/a]\ncredentials: [\"db:secrets/db\"]\n"},
		"unclean cred":     {"name: a\ncommand: [/usr/bin/a]\ncredentials: [\"db:/etc/../root/x\"]\n"},
		"dup cred":         {"name: a\ncommand: [/usr/bin/a]\ncredentials: [db, \"db:/x\"]\n"},
		"relative rw path": {"name: a\ncommand: [/usr/bin/a]\nsandbox:\n  read_write_paths: [var/lib/a]\n"},
		"unclean rw path":  {"name: a\ncommand: [/usr/bin/a]\nsandbox:\n  read_write_paths: [/var/lib/a/../mcp-gateway]\n"},
		"rw gateway state": {"name: a\ncommand: [/usr/bin/a]\nsandbox:\n  read_write_paths: [/var/lib/mcp-gateway/x]\n"},
		"rw above gateway": {"name: a\ncommand: [/usr/bin/a]\nsandbox:\n  read_write_paths: [/etc]\n"},
		"rw root":          {"name: a\ncommand: [/usr/bin/a]\nsandbox:\n  read_write_paths: [/]\n"},
		"absolute state":   {"name: a\ncommand: [/usr/bin/a]\nsandbox:\n  state_directory: /var/lib/a\n"},
		"dotdot state":     {"name: a\ncommand: [/usr/bin/a]\nsandbox:\n  state_directory: a/../../etc\n"},
		"gateway state":    {"name: a\ncommand: [/usr/bin/a]\nsandbox:\n  state_directory: mcp-gateway\n"},
		"duplicate":        {"name: a\ncommand: [/usr/bin/a]\n", "name: a\ncommand: [/usr/bin/b]\n"},
		"privileged user":  {"name: a\ncommand: [/usr/bin/a]\nprivileged: true\n"},
		"privileged rw":    {"name: a\ncommand: [/usr/bin/a]\nprivileged: true\nrun_as: root\nsandbox:\n  read_write_paths: [/srv]\n"},
	}
	for name, files := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for i, content := range files {
				writeFile(t, dir, strings.Repeat("x", i+1)+".yaml", content)
			}
			if _, err := LoadBackends(dir); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestVersion(t *testing.T) {
	dir := t.TempDir()
	g, err := LoadGateway(writeFile(t, dir, "gateway.yaml", "version: 1\n"))
	if err != nil || g.Version != Version {
		t.Fatalf("version 1: %v, %+v", err, g)
	}
	if g, err := LoadGateway(writeFile(t, dir, "none.yaml", "{}\n")); err != nil || g.Version != Version {
		t.Fatalf("no version: %v, %+v", err, g)
	}
	for _, tc := range []struct{ content, want string }{
		{"version: 2\n", "version: 2 is newer than this gateway reads (1)"},
		{"version: -1\n", "version: -1 is not supported"},
	} {
		if _, err := LoadGateway(writeFile(t, dir, "bad.yaml", tc.content)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: error %v, want %q", tc.content, err, tc.want)
		}
	}

	vendor := t.TempDir()
	writeFile(t, vendor, "a.yaml", "version: 1\nname: a\ncommand: [/usr/bin/a]\n")
	writeFile(t, vendor, "b.yaml", "name: b\ncommand: [/usr/bin/b]\n")
	bs, err := LoadBackends(vendor)
	if err != nil || bs["a"].Version != Version || bs["b"].Version != Version {
		t.Fatalf("backends: %v, %+v", err, bs)
	}
	writeFile(t, vendor, "c.yaml", "version: 2\nname: c\ncommand: [/usr/bin/c]\n")
	if _, err := LoadBackends(vendor); err == nil || !strings.Contains(err.Error(), "c.yaml: version: 2 is newer") {
		t.Errorf("backend version 2: %v", err)
	}
}

func TestDeprecations(t *testing.T) {
	defer func(g, b []deprecation) { gatewayDeprecations, backendDeprecations = g, b }(gatewayDeprecations, backendDeprecations)
	gatewayDeprecations = []deprecation{
		{Key: "supervisor.idle_timeout", Since: "0.4", Use: "write x instead"},
		{Key: "audit.kernel", Since: "0.4", Use: "write y instead"},
	}
	backendDeprecations = []deprecation{{Key: "network", Since: "0.4", Use: "write z instead"}}

	dir := t.TempDir()
	g, err := LoadGateway(writeFile(t, dir, "gateway.yaml", "supervisor:\n  idle_timeout: 5m\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := "supervisor.idle_timeout is deprecated since 0.4 and will be removed in the next minor release: write x instead"
	if len(g.Warnings) != 1 || g.Warnings[0] != want {
		t.Errorf("warnings %q, want [%q]", g.Warnings, want)
	}
	if g.Supervisor.IdleTimeout != 5*time.Minute {
		t.Errorf("deprecated key not read: %v", g.Supervisor.IdleTimeout)
	}

	servers := t.TempDir()
	writeFile(t, servers, "a.yaml", "name: a\ncommand: [/usr/bin/a]\nnetwork: true\n")
	writeFile(t, servers, "b.yaml", "name: b\ncommand: [/usr/bin/b]\nenv: {network: x}\n")
	bs, err := LoadBackends(servers)
	if err != nil {
		t.Fatal(err)
	}
	if len(bs["a"].Warnings) != 1 || len(bs["b"].Warnings) != 0 {
		t.Errorf("a %q, b %q", bs["a"].Warnings, bs["b"].Warnings)
	}
}

func TestMetricsListen(t *testing.T) {
	dir := t.TempDir()
	g, err := LoadGateway(writeFile(t, dir, "ok.yaml", "metrics:\n  listen: 127.0.0.1:9464\n"))
	if err != nil || g.Metrics.Listen != "127.0.0.1:9464" {
		t.Fatalf("%v, %+v", err, g.Metrics)
	}
	for _, bad := range []string{"9464", "localhost", "127.0.0.1:"} {
		if _, err := LoadGateway(writeFile(t, dir, "bad.yaml", "metrics:\n  listen: \""+bad+"\"\n")); err == nil || !strings.Contains(err.Error(), "metrics.listen") {
			t.Errorf("%q: error %v", bad, err)
		}
	}
}

func TestLoadBackendsDuplicateName(t *testing.T) {
	vendor, admin := t.TempDir(), t.TempDir()
	write := func(dir, file string) {
		def := "name: snapper\ncommand: [\"/usr/bin/mcp-server-snapper\"]\n"
		if err := os.WriteFile(filepath.Join(dir, file), []byte(def), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(vendor, "snapper.yaml")
	write(admin, "snapper-mcp.yaml")
	_, err := LoadBackends(vendor, admin)
	if err == nil {
		t.Fatal("duplicate server name accepted")
	}
	for _, want := range []string{
		filepath.Join(admin, "snapper-mcp.yaml"), filepath.Join(vendor, "snapper.yaml"),
		"rename yours to " + filepath.Join(admin, "snapper.yaml"),
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	// Under the package's file name, it replaces it.
	if err := os.Rename(filepath.Join(admin, "snapper-mcp.yaml"), filepath.Join(admin, "snapper.yaml")); err != nil {
		t.Fatal(err)
	}
	if bs, err := LoadBackends(vendor, admin); err != nil || len(bs) != 1 {
		t.Errorf("renamed: %v %v", bs, err)
	}
	// Both in one directory.
	write(vendor, "other.yaml")
	if _, err := LoadBackends(vendor); err == nil || !strings.Contains(err.Error(), "remove or rename one") {
		t.Errorf("same directory: %v", err)
	}
}

func TestBackendURL(t *testing.T) {
	ok := func(b Backend) *Backend {
		t.Helper()
		b.setDefaults()
		if err := b.Validate(); err != nil {
			t.Fatalf("%+v: %v", b, err)
		}
		return &b
	}
	b := ok(Backend{Name: "remote", URL: "https://mcp.example.com/mcp", Credentials: []string{"token"},
		Headers: map[string]string{"X-B": "2", "Authorization": "Bearer ${CREDENTIAL:token}"}})
	want := []string{HTTPConnector, "-url", "https://mcp.example.com/mcp",
		"-header", "Authorization: Bearer ${CREDENTIAL:token}", "-header", "X-B: 2"}
	if !slices.Equal(b.Command, want) || !b.Network || b.SELinuxType != HTTPSELinuxType || b.RunAs != HTTPRunAs {
		t.Errorf("defaults: %+v", b)
	}
	ok(Backend{Name: "local", URL: "http://127.0.0.1:8008/mcp", RunAs: "principal"})
	b = ok(Backend{Name: "proxied", URL: "https://mcp.example.com/mcp", Proxy: "http://proxy.example.com:3128",
		Credentials: []string{"proxy"}, ProxyHeaders: map[string]string{"Proxy-Authorization": "Basic ${CREDENTIAL:proxy}"}})
	want = []string{HTTPConnector, "-url", "https://mcp.example.com/mcp",
		"-proxy", "http://proxy.example.com:3128", "-proxy-header", "Proxy-Authorization: Basic ${CREDENTIAL:proxy}"}
	if !slices.Equal(b.Command, want) {
		t.Errorf("proxy command: %q", b.Command)
	}

	for _, c := range []struct {
		b   Backend
		err string
	}{
		{Backend{Name: "x", URL: "http://mcp.example.com/"}, "only to the local host"},
		{Backend{Name: "x", URL: "ftp://x/"}, "scheme"},
		{Backend{Name: "x", URL: "https://u:p@x/"}, "without user information"},
		{Backend{Name: "x", URL: "https://x/", Command: []string{"/bin/true"}}, "give one of them"},
		{Backend{Name: "x", URL: "https://x/", Privileged: true, RunAs: "root"}, "not with url"},
		{Backend{Name: "x", URL: "https://x/", Headers: map[string]string{"Bad Name": "v"}}, "not a header name"},
		{Backend{Name: "x", URL: "https://x/", Headers: map[string]string{"A": "a\nb"}}, "line break"},
		{Backend{Name: "x", URL: "https://x/", Headers: map[string]string{"A": "${CREDENTIAL:k}"}}, "does not list"},
		{Backend{Name: "x", Command: []string{"/bin/true"}, Headers: map[string]string{"A": "b"}}, "only with url"},
		{Backend{Name: "x", Command: []string{"/bin/true"}, Proxy: "http://p:3128"}, "proxy: only with url"},
		{Backend{Name: "x", URL: "http://127.0.0.1:8008/", Proxy: "http://p:3128"}, "only for an https:// url"},
		{Backend{Name: "x", URL: "https://x/", Proxy: "socks5://p:1080"}, "scheme must be http or https"},
		{Backend{Name: "x", URL: "https://x/", Proxy: "http://u:pw@p:3128"}, "without user information"},
		{Backend{Name: "x", URL: "https://x/", Proxy: "p:3128"}, "not a proxy URL"},
		{Backend{Name: "x", URL: "https://x/", ProxyHeaders: map[string]string{"A": "b"}}, "only with proxy"},
		{Backend{Name: "x", URL: "https://x/", Proxy: "http://p:3128", ProxyHeaders: map[string]string{"A": "${CREDENTIAL:k}"}}, "proxy_headers: A names the credential k"},
	} {
		c.b.setDefaults()
		if err := c.b.Validate(); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%+v: %v", c.b, err)
		}
	}
}

func TestBackendSignIn(t *testing.T) {
	b := Backend{Name: "tickets", URL: "https://mcp.example.com/mcp", SignIn: &SignIn{Scopes: []string{"read"}}}
	b.setDefaults()
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []string{HTTPConnector, "-url", "https://mcp.example.com/mcp", "-sign-in", "-header", "Authorization: Bearer ${CREDENTIAL:sign-in}"}
	if !slices.Equal(b.Command, want) || b.Discovery != DiscoveryInstance {
		t.Errorf("defaults: %q %s", b.Command, b.Discovery)
	}

	for _, c := range []struct {
		b   Backend
		err string
	}{
		{Backend{Name: "x", Command: []string{"/bin/true"}, SignIn: &SignIn{}}, "sign_in: only with url"},
		{Backend{Name: "x", URL: "https://x/", SignIn: &SignIn{}, Headers: map[string]string{"authorization": "Bearer x"}}, "Authorization header"},
		{Backend{Name: "x", URL: "https://x/", SignIn: &SignIn{}, Credentials: []string{"sign-in"}}, "use another name"},
		{Backend{Name: "x", URL: "https://x/", SignIn: &SignIn{ClientSecret: "s"}, Credentials: []string{"s"}}, "needs client_id"},
		{Backend{Name: "x", URL: "https://x/", SignIn: &SignIn{ClientID: "c", ClientSecret: "s"}}, "credentials does not list"},
		{Backend{Name: "x", URL: "https://x/", SignIn: &SignIn{Scopes: []string{"a b"}}}, "not a scope"},
		{Backend{Name: "x", URL: "https://x/", SignIn: &SignIn{}, Discovery: DiscoveryShared}, "discovery must be instance"},
	} {
		c.b.setDefaults()
		if err := c.b.Validate(); err == nil || !strings.Contains(err.Error(), c.err) {
			t.Errorf("%+v: %v", c.b, err)
		}
	}
	ok := Backend{Name: "x", URL: "https://x/", SignIn: &SignIn{ClientID: "c", ClientSecret: "s"}, Credentials: []string{"s"}}
	ok.setDefaults()
	if err := ok.Validate(); err != nil {
		t.Error(err)
	}
}

func TestCheckSignIn(t *testing.T) {
	backends := map[string]*Backend{"tickets": {Name: "tickets", SignIn: &SignIn{}}, "fs": {Name: "fs"}}
	g := &Gateway{}
	if err := CheckSignIn(g, backends); err == nil || !strings.Contains(err.Error(), "server tickets: sign_in needs the HTTP listener") {
		t.Errorf("no listener: %v", err)
	}
	g.HTTP = HTTP{Listen: ":8443", Audience: "https://gw.example.com:8443/mcp"}
	if err := CheckSignIn(g, backends); err != nil {
		t.Error(err)
	}
	if got := g.RedirectURI(); got != "https://gw.example.com:8443/oauth/callback" {
		t.Errorf("redirect %s", got)
	}
}
