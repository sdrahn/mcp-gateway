package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/doctor"
	"github.com/sdrahn/mcp-gateway/internal/httpsetup"
	"github.com/sdrahn/mcp-gateway/internal/policydata"
	"github.com/sdrahn/mcp-gateway/internal/statedir"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
	"github.com/sdrahn/mcp-gateway/internal/syscmd"
)

const setupUsage = `usage: mcp-gateway-admin setup http [flags]

Sets up the HTTP listener for remote agents and checks it end to end.
From the gateway's public URL and the identity provider's issuer it
fills in the http block of gateway.yaml (with -write; without, it shows
what it would change), keeping the keys it does not ask about. Then it
checks what else has to be right: the identity provider's metadata and
keys, as the gateway fetches them; the certificate and key, as the
gateway's account and SELinux domain read them; the SELinux labels of
the port and of the identity provider's port; firewalld; with -token, an
access token as the gateway takes it (whom it makes the principal, with
which groups and scopes, the ceiling its scopes set in the role data,
or why it is refused); and the listener, as a client
reaches it. Flags left out keep what the http block has, so
"setup http -token FILE" alone checks a running setup.
Run it as root. Exits 1 if a check failed, 2 on bad flags, 0 otherwise.

`

// runSetup is "mcp-gateway-admin setup TOPIC".
func runSetup(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "http" {
		if len(args) > 0 && (args[0] == "-h" || args[0] == "-help" || args[0] == "--help") {
			_, _ = fmt.Fprint(stdout, setupUsage)
			return 0
		}
		_, _ = fmt.Fprint(stderr, setupUsage)
		return 2
	}
	return runSetupHTTP(args[1:], stdout, stderr)
}

func runSetupHTTP(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp-gateway-admin setup http", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, setupUsage)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", config.DefaultConfigPath, "gateway configuration to set up (a missing one starts from the package default)")
	var a httpsetup.Answers
	fs.StringVar(&a.URL, "url", "", "the gateway's public MCP URL, as clients use it, e.g. https://gw.example.com:8443/mcp (http.audience; http.listen takes its port)")
	fs.StringVar(&a.Issuer, "issuer", "", "the identity provider's issuer URL, e.g. https://idp.example.com/realms/mcp (http.issuer)")
	fs.StringVar(&a.CertFile, "cert", "", "certificate file, PEM with the chain (http.cert_file)")
	fs.StringVar(&a.KeyFile, "key", "", "private key file, PEM (http.key_file)")
	fs.StringVar(&a.GroupsClaim, "groups-claim", "", "token claim with the principal's groups (http.groups_claim; default groups)")
	fs.StringVar(&a.LocalUserClaim, "local-user-claim", "", "token claim naming a local account to act as, e.g. preferred_username (http.local_user_claim)")
	scopes := fs.String("scopes", "", "comma-separated scopes every token must carry, e.g. mcp (http.scopes; \"\" for none)")
	tokenFile := fs.String("token", "", "file with an access token to check as the gateway takes it, - for standard input")
	policyData := fs.String("policy-data", policydata.DefaultPath, "role data, for the ceiling of the token's scopes (empty: none)")
	write := fs.Bool("write", false, "write the http block to the configuration")
	timeout := fs.Duration("timeout", 10*time.Second, "how long to wait for the identity provider and the listener")
	asJSON := fs.Bool("json", false, "print the results as JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "scopes" {
			a.Scopes = []string{}
			for _, s := range strings.Split(*scopes, ",") {
				if s = strings.TrimSpace(s); s != "" {
					a.Scopes = append(a.Scopes, s)
				}
			}
		}
	})

	cur, err := currentHTTP(*configPath)
	if err != nil {
		say(stderr, "mcp-gateway-admin setup http:", err)
		return 1
	}
	h, err := httpsetup.Block(cur, a)
	if err != nil {
		sayf(stderr, "mcp-gateway-admin setup http: %v", err)
		return 2
	}
	if h.GroupsClaim == "" {
		h.GroupsClaim = config.DefaultGroupsClaim
	}
	token := ""
	if *tokenFile != "" {
		if token, err = readToken(*tokenFile); err != nil {
			say(stderr, "mcp-gateway-admin setup http:", err)
			return 1
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4**timeout)
	defer cancel()
	// The gateway reaches the identity provider directly, never through
	// a proxy from the environment: so do the checks.
	client := &http.Client{Timeout: *timeout, Transport: &http.Transport{Proxy: nil}}
	root := os.Geteuid() == 0

	var rs []doctor.Result
	rs = append(rs, blockResult(*configPath, cur, h, *write))
	rs = append(rs, httpsetup.IdentityProvider(ctx, h, client)...)
	rs = append(rs, setupTLS(h, root)...)
	rs = append(rs, setupPorts(h, root)...)
	rs = append(rs, setupFirewall(h, root)...)
	if token != "" {
		var roleData []byte
		if *policyData != "" {
			// Unreadable role data (no administrative access) leaves the
			// ceiling out.
			roleData, _ = os.ReadFile(*policyData)
		}
		rs = append(rs, httpsetup.Token(ctx, h, client, token, roleData)...)
	}
	rs = append(rs, httpsetup.Listener(ctx, h, client, token)...)
	doctor.Identify(rs)
	if *asJSON {
		err = doctor.WriteJSON(stdout, rs)
	} else {
		err = doctor.WriteText(stdout, rs, colorful(stdout))
	}
	if err != nil {
		say(stderr, err)
		return 1
	}
	return doctorExit(rs, false)
}

// currentHTTP returns the http block of the configuration at path, or
// of the package default if path does not exist.
func currentHTTP(path string) (config.HTTP, error) {
	p := path
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) && path == config.DefaultConfigPath {
		p = config.DefaultVendorConfigPath
	}
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		return config.HTTP{}, nil
	}
	gw, err := config.LoadGateway(p)
	if err != nil {
		return config.HTTP{}, err
	}
	return gw.HTTP, nil
}

func readToken(path string) (string, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return "", err
	}
	t := strings.TrimSpace(string(data))
	t = strings.TrimSpace(strings.TrimPrefix(t, "Bearer "))
	if t == "" {
		return "", fmt.Errorf("%s: no token", path)
	}
	return t, nil
}

// blockResult writes the http block (with write) or says what writing
// it would change.
func blockResult(path string, cur, h config.HTTP, write bool) doctor.Result {
	r := doctor.Result{Check: "http block", Status: doctor.OK}
	if !write {
		data, _ := os.ReadFile(path)
		if len(data) == 0 {
			data, _ = os.ReadFile(config.DefaultVendorConfigPath)
		}
		_, changes, err := httpsetup.Edit(data, h)
		switch {
		case err != nil:
			r.Status, r.Summary = doctor.Fail, fmt.Sprintf("%s: %v", path, err)
		case len(changes) == 0:
			r.Summary = path + " has this http block"
		default:
			r.Status, r.Summary = doctor.Warn, "not written yet: run again with -write to set in "+path+":"
			r.Details = changeLines(changes)
		}
		return r
	}
	changes, err := httpsetup.Write(path, config.DefaultVendorConfigPath, h)
	switch {
	case err != nil:
		r.Status, r.Summary = doctor.Fail, err.Error()
	case len(changes) == 0:
		r.Summary = path + " has this http block already"
	default:
		r.Summary = "wrote " + path + ":"
		r.Details = changeLines(changes)
		if cur.Listen != h.Listen {
			r.Details = append(r.Details, "http.listen takes effect at start: systemctl restart mcp-gateway.service (the checks below see the gateway as it runs now)")
		}
	}
	return r
}

func changeLines(cs []httpsetup.Change) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		if c.Old == "" {
			out = append(out, fmt.Sprintf("%s: %s", c.Key, c.New))
		} else {
			out = append(out, fmt.Sprintf("%s: %s (was %s)", c.Key, c.New, c.Old))
		}
	}
	return out
}

// setupTLS checks the certificate and key as the gateway's account
// reads them (doctor.TLS); the key is that account's alone, so only
// root checks it.
func setupTLS(h config.HTTP, root bool) []doctor.Result {
	if !root {
		return []doctor.Result{{Check: "TLS", Status: doctor.Skip, Summary: "the key is the gateway's alone: run setup http as root"}}
	}
	acct, err := gatewayAccount()
	if err != nil {
		return []doctor.Result{{Check: "TLS", Status: doctor.Skip, Summary: err.Error()}}
	}
	var types func(string) (string, error)
	if supervisor.SELinuxEnabled() {
		types = fileType
	}
	return doctor.TLS(h, acct, types, time.Now())
}

// gatewayAccount is the gateway's account, which must read the
// certificate and key.
func gatewayAccount() (doctor.Account, error) {
	u, err := user.Lookup(statedir.User)
	if err != nil {
		return doctor.Account{}, fmt.Errorf("no %s account", statedir.User)
	}
	acct := doctor.Account{Name: u.Username}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	acct.UID, acct.GID = uint32(uid), uint32(gid)
	if ids, err := u.GroupIds(); err == nil {
		for _, id := range ids {
			if g, err := strconv.ParseUint(id, 10, 32); err == nil {
				acct.Groups = append(acct.Groups, uint32(g))
			}
		}
	}
	return acct, nil
}

// setupPorts checks the SELinux labels of the listener's and the
// identity provider's ports (httpsetup.SELinuxPorts) with semanage.
func setupPorts(h config.HTTP, root bool) []doctor.Result {
	if !supervisor.SELinuxEnabled() {
		return nil
	}
	semanage, err := syscmd.Path("semanage")
	if err != nil {
		return []doctor.Result{{Check: "SELinux port", Status: doctor.Skip, Summary: "no semanage (package policycoreutils-python-utils) to read the port labels"}}
	}
	if !root {
		return []doctor.Result{{Check: "SELinux port", Status: doctor.Skip, Summary: "semanage needs root: run setup http as root"}}
	}
	out, err := exec.Command(semanage, "port", "-l", "-n").Output()
	if err != nil {
		return []doctor.Result{{Check: "SELinux port", Status: doctor.Skip, Summary: "semanage port -l: " + err.Error()}}
	}
	return httpsetup.SELinuxPorts(h, string(out))
}

// setupFirewall checks that firewalld lets the port in (doctor.Firewall).
func setupFirewall(h config.HTTP, root bool) []doctor.Result {
	if _, err := exec.LookPath("firewall-cmd"); err != nil {
		return nil
	}
	if !root {
		return []doctor.Result{{Check: "firewall", Status: doctor.Skip, Summary: "firewall-cmd needs root: run setup http as root"}}
	}
	return doctor.Firewall(h.Listen, func(args ...string) (string, error) {
		out, err := exec.Command("firewall-cmd", args...).Output()
		return string(out), err
	})
}
