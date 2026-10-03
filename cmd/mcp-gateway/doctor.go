package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/doctor"
	"github.com/sdrahn/mcp-gateway/internal/inspect"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/policydata"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/profile"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
)

const doctorUsage = `usage: mcp-gateway doctor [flags]

Checks the installation for what usually goes wrong with MCP servers
behind the gateway: the configuration and role data, the services and
OPA, state files the service cannot read (left by running the gateway
as root), servers that do not start (each registered server is started
once, as for shared discovery), roles naming tools a server does not
have, SELinux denials for the gateway and its servers, servers running
as an account no polkit rule names, a snapper server no snapper config
allows, and users who may connect but hold no role. Run it as root;
without root, the checks that need it are skipped. Exits 1 if a check
failed.

`

func runDoctor(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp-gateway doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, doctorUsage)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "", "gateway configuration")
	policyData := fs.String("policy-data", policydata.DefaultPath, "role data")
	shipped := fs.String("shipped-policy", policydata.DefaultShippedDir, "shipped policy with the roles of the server setups")
	only := fs.String("server", "", "check only this server (start, roles)")
	noStart := fs.Bool("no-start", false, "do not start the servers")
	since := fs.Duration("since", 24*time.Hour, "how far back to look for SELinux denials")
	timeout := fs.Duration("timeout", 30*time.Second, "how long to wait for each server")
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
	d := &doctorRun{
		root:       os.Geteuid() == 0,
		policyData: *policyData,
		shipped:    *shipped,
		only:       *only,
		noStart:    *noStart,
		since:      *since,
		timeout:    *timeout,
		log:        slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	rs := d.run(*configPath)
	write := doctor.WriteText
	if *asJSON {
		write = doctor.WriteJSON
	}
	if err := write(stdout, rs); err != nil {
		say(stderr, err)
		return 1
	}
	if doctor.Failed(rs) {
		return 1
	}
	return 0
}

type doctorRun struct {
	root bool
	// isolated is the doctor of the gateway-admin server, which like every
	// server cannot reach the gateway's sockets or OPA.
	isolated            bool
	policyData, shipped string
	only                string
	noStart             bool
	since, timeout      time.Duration
	log                 *slog.Logger

	gw       *config.Gateway
	backends map[string]*config.Backend
	rbac     []byte // the role data, if read
}

func (d *doctorRun) run(configPath string) []doctor.Result {
	var rs []doctor.Result
	add := func(r ...doctor.Result) { rs = append(rs, r...) }

	add(d.configuration(configPath))
	if d.gw == nil {
		return rs
	}
	if d.only != "" && d.backends[d.only] == nil {
		add(doctor.Result{Check: "server " + d.only, Status: doctor.Fail, Summary: "not in the registry"})
		return rs
	}
	add(d.roleData())
	add(d.services()...)
	add(d.stateFiles())
	if d.isolated {
		add(doctor.Result{Check: "policy", Status: doctor.Skip,
			Summary: "servers cannot reach OPA (mcp-gateway doctor as root asks it; explain_decision evaluates the policy files)"})
	} else {
		add(d.opa())
	}
	add(d.servers()...)
	add(d.selinux()...)
	if supervisor.SELinuxEnabled() {
		add(doctor.SELinuxTypes(d.selected(), supervisor.ContextValid)...)
		add(doctor.ProgramLabels(d.selected(), fileType, policyType, readOnly)...)
	}
	add(doctor.ReadOnlyRoot(d.selected(), readOnly("/usr"))...)
	add(doctor.Polkit(d.selected(), nil)...)
	add(doctor.Snapper(d.selected(), doctor.SnapperConfigsDir, userGroups)...)
	add(d.principals())
	return rs
}

// selected returns the servers to check (-server, or all).
func (d *doctorRun) selected() map[string]*config.Backend {
	if d.only == "" {
		return d.backends
	}
	return map[string]*config.Backend{d.only: d.backends[d.only]}
}

func (d *doctorRun) configuration(path string) doctor.Result {
	r := doctor.Result{Check: "configuration"}
	gw, used, err := config.Resolve(path)
	if err != nil {
		r.Status, r.Summary = doctor.Fail, err.Error()
		return r
	}
	if used == "" {
		used = "built-in defaults"
	}
	backends, err := config.LoadBackends(gw.VendorServersDir, gw.ServersDir)
	if err != nil {
		r.Status, r.Summary = doctor.Fail, "server definitions: "+err.Error()
		return r
	}
	d.gw, d.backends = gw, backends
	r.Status = doctor.OK
	r.Summary = fmt.Sprintf("%s, %d servers", used, len(backends))
	if len(backends) > 0 {
		r.Summary += " (" + strings.Join(slices.Sorted(maps.Keys(backends)), ", ") + ")"
	}
	r.Details = append(r.Details, gw.Warnings...)
	for _, name := range slices.Sorted(maps.Keys(backends)) {
		for _, w := range backends[name].Warnings {
			r.Details = append(r.Details, name+": "+w)
		}
	}
	if len(r.Details) > 0 {
		r.Status = doctor.Warn
	}
	return r
}

func (d *doctorRun) roleData() doctor.Result {
	r := doctor.Result{Check: "role data"}
	data, err := os.ReadFile(d.policyData)
	if errors.Is(err, fs.ErrNotExist) {
		r.Status, r.Summary = doctor.Warn, d.policyData+" does not exist (policy from a bundle?): not checked"
		return r
	}
	if err != nil {
		return skipOrFail(r, err)
	}
	d.rbac = data
	var shipped map[string]string
	var problems []string
	if d.shipped != "" {
		if shipped, problems, err = policydata.ShippedRoles(d.shipped); err != nil {
			r.Status, r.Summary = doctor.Fail, err.Error()
			return r
		}
	}
	own, err := policydata.CheckWith(data, shipped)
	if err != nil {
		r.Status, r.Summary = doctor.Fail, err.Error()
		return r
	}
	problems = append(problems, own...)
	if len(problems) > 0 {
		r.Status, r.Summary, r.Details = doctor.Fail, fmt.Sprintf("%s: %d problems; the policy treats invalid data as absent", d.policyData, len(problems)), problems
		return r
	}
	r.Status, r.Summary = doctor.OK, fmt.Sprintf("%s valid (%d shipped roles known)", d.policyData, len(shipped))
	return r
}

// services checks the units and asks the running gateway for its state.
func (d *doctorRun) services() []doctor.Result {
	var rs []doctor.Result
	if _, err := exec.LookPath("systemctl"); err == nil {
		for _, unit := range []string{"mcp-gateway.service", "mcp-opa.service"} {
			out, _ := exec.Command("systemctl", "is-active", unit).Output()
			state := strings.TrimSpace(string(out))
			if state == "" {
				state = "unknown (systemd not reachable)"
			}
			r := doctor.Result{Check: unit, Status: doctor.OK, Summary: state}
			if state != "active" {
				r.Status = doctor.Fail
				r.Details = []string{"journalctl -u " + unit + " shows why"}
			}
			rs = append(rs, r)
		}
	}
	if sock := d.gw.Approvals.ControlSocket; sock != "-" && !d.isolated {
		r := doctor.Result{Check: "gateway status"}
		var st struct {
			Version        string `json:"version"`
			RestartPending bool   `json:"restart_pending"`
		}
		if err := controlGet(sock, "/v1/status", &st); err != nil {
			rs = append(rs, skipOrFail(r, err))
		} else {
			r.Status, r.Summary = doctor.OK, "running version "+orDash(st.Version)
			if st.RestartPending {
				r.Status = doctor.Warn
				r.Summary += "; updated since its start: systemctl restart mcp-gateway.service"
			}
			rs = append(rs, r)
		}
	}
	return rs
}

// stateFiles finds files in the gateway's state directory that its
// account does not own, usually left by running the gateway as root: the
// service then fails to read them at start. (/run/mcp-gateway also holds
// OPA's socket; the gateway replaces a stale socket of its own whoever
// owns it.)
func (d *doctorRun) stateFiles() doctor.Result {
	r := doctor.Result{Check: "state files"}
	u, err := user.Lookup(gatewayUser)
	if err != nil {
		r.Status, r.Summary = doctor.Skip, "no "+gatewayUser+" account"
		return r
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	dir := d.gw.StateDir
	foreign, err := foreignFiles(dir, uint32(uid))
	if err != nil && d.isolated && errors.Is(err, fs.ErrPermission) {
		r.Status, r.Summary = doctor.Skip, dir+" is the gateway's alone (0700), and this server has no capabilities: mcp-gateway doctor as root checks it"
		return r
	}
	if err != nil {
		return skipOrFail(r, err)
	}
	for _, f := range foreign {
		r.Details = append(r.Details, f.String())
	}
	if len(r.Details) > 0 {
		r.Status = doctor.Fail
		r.Summary = fmt.Sprintf("not owned by %s: %d (was the gateway run as root?); the service fails to read them: chown -R %s: %s",
			gatewayUser, len(r.Details), gatewayUser, dir)
		return r
	}
	r.Status, r.Summary = doctor.OK, dir+" owned by "+gatewayUser
	return r
}

// opa asks OPA for a decision a principal named mcp-doctor would get.
func (d *doctorRun) opa() doctor.Result {
	r := doctor.Result{Check: "policy"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opa := pep.NewOPA(d.gw.Policy.OPASocket, 5*time.Second)
	dec, err := opa.Decide(ctx, pep.Input{
		Principal: principal.Principal{Sub: "mcp-doctor", Transport: principal.TransportInternal},
		Action:    "tools.call",
		Resource:  pep.Resource{Server: "mcp-doctor", Kind: "tool", Name: "probe"},
	})
	if err != nil {
		if errors.Is(err, fs.ErrPermission) && !d.root {
			r.Status, r.Summary = doctor.Skip, "OPA's socket needs root"
			return r
		}
		r.Status, r.Summary = doctor.Fail, "OPA does not decide: "+err.Error()
		r.Details = []string{"every request is denied while this fails; journalctl -u mcp-opa.service"}
		return r
	}
	if err := dec.Validate(); err != nil {
		r.Status, r.Summary = doctor.Fail, "OPA's decision is invalid: "+err.Error()
		return r
	}
	r.Status, r.Summary = doctor.OK, fmt.Sprintf("OPA decides (%s for an unknown principal)", dec.Effect)
	return r
}

// servers starts each server once and checks the role data against the
// tools it has.
func (d *doctorRun) servers() []doctor.Result {
	sel := d.selected()
	if d.noStart {
		return []doctor.Result{{Check: "servers", Status: doctor.Skip, Summary: "not started (-no-start)"}}
	}
	if d.gw.Supervisor.Mode == "systemd" && !d.root {
		return []doctor.Result{{Check: "servers", Status: doctor.Skip, Summary: "starting servers through systemd needs root"}}
	}
	launcher, err := newLauncher(d.log, d.gw.Supervisor)
	if err != nil {
		return []doctor.Result{{Check: "servers", Status: doctor.Fail, Summary: err.Error()}}
	}
	roleFiles := d.roleFiles()
	var rs []doctor.Result
	for _, name := range slices.Sorted(maps.Keys(sel)) {
		b := sel[name]
		r := doctor.Result{Check: "server " + name}
		ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
		res, err := probe(ctx, launcher, b, principal.Discovery)
		cancel()
		if err != nil {
			r.Status, r.Summary = doctor.Fail, "does not start: "+err.Error()
			r.Details = []string{fmt.Sprintf("journalctl -u 'mcp-%s-*' shows its output; mcp-gateway inspect -server %s for more", name, name)}
			rs = append(rs, r)
			continue
		}
		r.Status = doctor.OK
		r.Summary = fmt.Sprintf("starts: %s %s, %d tools, %d prompts, %d resource templates",
			orDash(res.Server.Name), res.Server.Version, len(res.Tools), len(res.Prompts), len(res.ResourceTemplates))
		if len(res.Tools) == 0 {
			r.Status = doctor.Warn
			r.Summary += " (no tools: as the account it runs as, the server may hide them)"
		}
		rs = append(rs, r)
		if len(roleFiles) > 0 {
			findings, err := inspect.CheckRoles(roleFiles, name, res)
			if err != nil {
				rs = append(rs, doctor.Result{Check: "roles " + name, Status: doctor.Fail, Summary: err.Error()})
				continue
			}
			var msgs []string
			for _, f := range findings {
				if f.Level == "error" {
					msgs = append(msgs, f.Message)
				}
			}
			if len(msgs) > 0 {
				rs = append(rs, doctor.Result{Check: "roles " + name, Status: doctor.Warn,
					Summary: fmt.Sprintf("%d permissions name what %s does not offer (to the account it runs as)", len(msgs), name),
					Details: msgs})
			}
		}
	}
	return rs
}

// roleFiles are the role data and the shipped setups' roles.
func (d *doctorRun) roleFiles() []inspect.RoleFile {
	var files []inspect.RoleFile
	if d.rbac != nil {
		files = append(files, inspect.RoleFile{Name: d.policyData, Data: d.rbac})
	}
	if d.shipped != "" {
		paths, _ := filepath.Glob(filepath.Join(d.shipped, "mcp", "profiles", "*", "data.json"))
		for _, p := range paths {
			if data, err := os.ReadFile(p); err == nil {
				files = append(files, inspect.RoleFile{Name: p, Data: data})
			}
		}
	}
	return files
}

func (d *doctorRun) selinux() []doctor.Result {
	if !d.root {
		return []doctor.Result{{Check: "SELinux", Status: doctor.Skip, Summary: "reading the audit log needs root"}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	raw, err := profile.ReadAudit(ctx)
	if err != nil {
		return []doctor.Result{{Check: "SELinux", Status: doctor.Skip, Summary: "reading the audit log: " + err.Error()}}
	}
	from := time.Now().Add(-d.since)
	denials, errs := profile.Parse(raw, from)
	return doctor.Denials(denials, errs, from.Format(time.DateTime))
}

// principals finds members of the socket group without a role.
func (d *doctorRun) principals() doctor.Result {
	r := doctor.Result{Check: "principals"}
	group := d.gw.SocketGroup
	if group == "" || d.rbac == nil {
		r.Status, r.Summary = doctor.Skip, "no socket_group, or no role data"
		return r
	}
	members, err := groupMembers(group)
	if err != nil {
		r.Status, r.Summary = doctor.Skip, err.Error()
		return r
	}
	var data struct {
		Bindings doctor.Bindings `json:"bindings"`
	}
	_ = json.Unmarshal(d.rbac, &data)
	unbound := doctor.Unbound(members, userGroups, data.Bindings)
	if len(unbound) > 0 {
		r.Status = doctor.Warn
		r.Summary = fmt.Sprintf("%d of %d members of %s hold no role: they may connect but see no server", len(unbound), len(members), group)
		r.Details = []string{strings.Join(unbound, ", ")}
		return r
	}
	r.Status, r.Summary = doctor.OK, fmt.Sprintf("all %d members of %s hold a role (remote principals are not checked)", len(members), group)
	return r
}

// groupMembers lists a group's members through NSS (getent; users whose
// primary group it is are not listed).
func groupMembers(group string) ([]string, error) {
	out, err := exec.Command("getent", "group", group).Output()
	if err != nil {
		return nil, fmt.Errorf("group %s not found", group)
	}
	fields := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(fields) < 4 || fields[3] == "" {
		return nil, nil
	}
	return strings.Split(fields[3], ","), nil
}

// userGroups returns the names of a user's groups.
func userGroups(name string) []string {
	u, err := user.Lookup(name)
	if err != nil {
		return nil
	}
	ids, err := u.GroupIds()
	if err != nil {
		return nil
	}
	var out []string
	for _, id := range ids {
		if g, err := user.LookupGroupId(id); err == nil {
			out = append(out, g.Name)
		}
	}
	return out
}

// controlGet fetches a control API path.
func controlGet(sock, path string, v any) error {
	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
	resp, err := c.Get("http://gw" + path)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// skipOrFail: a permission error without root skips, anything else fails.
func skipOrFail(r doctor.Result, err error) doctor.Result {
	if errors.Is(err, fs.ErrPermission) && os.Geteuid() != 0 {
		r.Status, r.Summary = doctor.Skip, "needs root: "+err.Error()
		return r
	}
	r.Status, r.Summary = doctor.Fail, err.Error()
	return r
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
