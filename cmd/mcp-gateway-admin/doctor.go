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
	"github.com/sdrahn/mcp-gateway/internal/notify"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/policydata"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/profile"
	"github.com/sdrahn/mcp-gateway/internal/statedir"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
	"golang.org/x/sys/unix"
)

const doctorUsage = `usage: mcp-gateway-admin doctor [flags]

Checks the installation for what usually goes wrong with MCP servers
behind the gateway: the configuration and role data, the services and
OPA, state files the service cannot read (left by running the gateway
as root), servers that do not start (each registered server is started
once, as for shared discovery), roles naming tools a server does not
have, SELinux denials for the gateway and its servers, servers running
as an account no polkit rule names, a snapper server no snapper config
allows, users who may connect but hold no role, and approver groups in
which approval mail finds nobody. A warning names
what to change; what the doctor cannot tell is wrong is OK, with a note.
Run it as root; without root, the checks that need it are skipped.
Exits 1 if a check failed, 3 with -strict if one warned, 0 otherwise.

`

func runDoctor(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp-gateway-admin doctor", flag.ContinueOnError)
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
	since := fs.Duration("since", 24*time.Hour, "how far back to look for SELinux denials (within the current boot)")
	previousBoots := fs.Bool("previous-boots", false, "with -since, also count SELinux denials from before the current boot")
	timeout := fs.Duration("timeout", 30*time.Second, "how long to wait for each server")
	asJSON := fs.Bool("json", false, "print the results as JSON")
	strict := fs.Bool("strict", false, "exit 3 if a check warned (and none failed)")
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
		allBoots:   *previousBoots,
		timeout:    *timeout,
		log:        slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	rs := d.run(*configPath)
	doctor.Identify(rs)
	var err error
	if *asJSON {
		err = doctor.WriteJSON(stdout, rs)
	} else {
		err = doctor.WriteText(stdout, rs, colorful(stdout))
	}
	if err != nil {
		say(stderr, err)
		return 1
	}
	return doctorExit(rs, *strict)
}

// doctorExit is the doctor's exit status: 1 if a check failed, 3 if one
// warned and strict is set, else 0.
func doctorExit(rs []doctor.Result, strict bool) int {
	switch {
	case doctor.Failed(rs):
		return 1
	case strict && doctor.Warned(rs):
		return 3
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
	// allBoots counts denials from before the current boot too.
	allBoots bool
	log      *slog.Logger

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
			Summary: "servers cannot reach OPA (mcp-gateway-admin doctor as root asks it; explain_decision evaluates the policy files)"})
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
	add(d.approverGroups()...)
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
		// The running gateway keeps the definitions it had (it reports
		// that as its status); the other checks go on without servers.
		d.gw, d.backends = gw, map[string]*config.Backend{}
		r.Status, r.Summary = doctor.Fail, "server definitions: "+err.Error()
		r.Details = []string{"a running gateway keeps serving the definitions it loaded before; fix the file, and it reloads by itself"}
		return r
	}
	d.gw, d.backends = gw, backends
	if err := config.CheckSignIn(gw, backends); err != nil {
		r.Status, r.Summary = doctor.Fail, err.Error()
		r.Details = []string{"set http.listen and http.audience (user guide, chapter 3, Remote access), or remove sign_in"}
		return r
	}
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
		r.Status, r.Summary = doctor.Skip, d.policyData+" does not exist (policy from a bundle?): not checked"
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
		rs = append(rs, gatewayStatus(sock))
	}
	return rs
}

// gatewayStatus asks the running gateway for its version, whether it was
// updated since its start and whether its server definitions reloaded.
func gatewayStatus(sock string) doctor.Result {
	r := doctor.Result{Check: "gateway status"}
	var st struct {
		Version        string   `json:"version"`
		RestartPending bool     `json:"restart_pending"`
		ServersError   string   `json:"servers_error"`
		ConfigError    string   `json:"config_error"`
		RestartNeeded  []string `json:"restart_needed"`
	}
	if err := controlGet(sock, "/v1/status", &st); err != nil {
		return skipOrFail(r, err)
	}
	r.Status, r.Summary = doctor.OK, "running version "+orDash(st.Version)
	if st.RestartPending {
		r.Status = doctor.Warn
		r.Summary += "; updated since its start: systemctl restart mcp-gateway.service"
	}
	if st.ServersError != "" {
		r.Status = doctor.Warn
		r.Summary += "; server definitions not reloaded, it serves the previous ones"
		r.Details = append(r.Details, st.ServersError, "fix the file (mcp-gateway --check shows the problem); the gateway reloads by itself")
	}
	if st.ConfigError != "" {
		r.Status = doctor.Warn
		r.Summary += "; gateway.yaml not reloaded, it runs with the configuration it had"
		r.Details = append(r.Details, st.ConfigError, "fix the file (mcp-gateway --check shows the problem); the gateway reloads by itself")
	}
	if len(st.RestartNeeded) > 0 {
		r.Status = doctor.Warn
		r.Summary += "; gateway.yaml changes keys that take effect at the next start: systemctl restart mcp-gateway.service"
		r.Details = append(r.Details, "changed since the start: "+strings.Join(st.RestartNeeded, ", "))
	}
	return r
}

// stateFiles finds files in the gateway's state directory that its
// account does not own, usually left by running the gateway as root: the
// service then fails to read them at start. (/run/mcp-gateway also holds
// OPA's socket; the gateway replaces a stale socket of its own whoever
// owns it.)
func (d *doctorRun) stateFiles() doctor.Result {
	r := doctor.Result{Check: "state files"}
	u, err := user.Lookup(statedir.User)
	if err != nil {
		r.Status, r.Summary = doctor.Skip, "no "+statedir.User+" account"
		return r
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	dir := d.gw.StateDir
	foreign, err := statedir.ForeignFiles(dir, uint32(uid))
	if err != nil && d.isolated && errors.Is(err, fs.ErrPermission) {
		r.Status, r.Summary = doctor.Skip, dir+" is the gateway's alone (0700), and this server has no capabilities: mcp-gateway-admin doctor as root checks it"
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
			statedir.User, len(r.Details), statedir.User, dir)
		return r
	}
	r.Status, r.Summary = doctor.OK, dir+" owned by "+statedir.User
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
	launcher, err := supervisor.NewLauncher(d.log, d.gw.Supervisor)
	if err != nil {
		return []doctor.Result{{Check: "servers", Status: doctor.Fail, Summary: err.Error()}}
	}
	roleFiles := d.roleFiles()
	var rs []doctor.Result
	for _, name := range slices.Sorted(maps.Keys(sel)) {
		b := sel[name]
		r := doctor.Result{Check: "server " + name}
		ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
		res, err := inspect.Start(ctx, launcher, b, principal.Discovery)
		cancel()
		if err != nil {
			r.Status, r.Summary = doctor.Fail, "does not start: "+err.Error()
			r.Details = []string{fmt.Sprintf("journalctl -u 'mcp-%s-*' shows its output; mcp-gateway-admin inspect --server %s for more", name, name)}
			rs = append(rs, r)
			continue
		}
		r.Status = doctor.OK
		r.Summary = fmt.Sprintf("starts: %s %s, %d tools, %d prompts, %d resource templates",
			orDash(res.Server.Name), res.Server.Version, len(res.Tools), len(res.Prompts), len(res.ResourceTemplates))
		if len(res.Tools) == 0 {
			r.Status = doctor.Warn
			r.Summary += " (no tools)"
			r.Details = []string{fmt.Sprintf("see what it offers: mcp-gateway-admin inspect --server %s; a server may offer", name),
				"its tools only to root, which needs a privileged definition (chapter 4), or none without its configuration"}
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
			if r := rolesResult(name, res.Server.Version, b.RunAs, msgs); r != nil {
				rs = append(rs, *r)
			}
		}
	}
	return rs
}

// rolesResult reports role permissions naming tools that server name (at
// version, running as runAs) did not offer, or nil if there are none. The
// two usual causes go into the details: a server that is not root may
// hide the tools only root can use, and another version of the server may
// name its tools differently than the roles expect.
func rolesResult(name, version, runAs string, msgs []string) *doctor.Result {
	if len(msgs) == 0 {
		return nil
	}
	server := name
	if version != "" {
		server += " " + version
	}
	account := runAs
	if account == config.DefaultRunAs {
		account = "the discovery account"
	}
	details := slices.Clone(msgs)
	if runAs != "root" {
		details = append(details, "a server not running as root may offer some tools only to root: roles for them need a "+
			"privileged definition of the server (chapter 4), and are reported here otherwise")
	}
	details = append(details, fmt.Sprintf("tools missing for any account usually mean another version of the server "+
		"than the roles were written for: compare with mcp-gateway-admin inspect --server %s", name))
	return &doctor.Result{Check: "roles " + name, Status: doctor.Warn,
		Summary: fmt.Sprintf("%d permissions name what %s does not offer to %s", len(msgs), server, account),
		Details: details}
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
	from, label := denialWindow(time.Now(), d.since, bootTime(), d.allBoots)
	denials, errs := profile.Parse(raw, from)
	return doctor.Denials(denials, errs, label)
}

// colorful reports whether to color the output for w: a terminal, unless
// NO_COLOR is set (https://no-color.org) or TERM is dumb.
func colorful(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// denialWindow returns since when denials count, and how to name that:
// since ago, but not before the current boot (unless allBoots). Denials
// from before a reboot were made by the policy and labels of then; on
// transactional systems, a module installed with the packages takes
// effect at the next boot, so those denials are expected and gone.
func denialWindow(now time.Time, since time.Duration, boot time.Time, allBoots bool) (time.Time, string) {
	from := now.Add(-since)
	if !allBoots && boot.After(from) {
		return boot, boot.Format(time.DateTime) + " (the current boot; -previous-boots for earlier ones)"
	}
	return from, from.Format(time.DateTime)
}

// bootTime is when the system booted (btime in /proc/stat), or the zero
// time if unknown.
func bootTime() time.Time {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "btime "); ok {
			if s, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return time.Unix(s, 0)
			}
		}
	}
	return time.Time{}
}

// approverGroups checks, when approval mail is on, that the doctor finds
// members in each approver group (group: rules) as the mail does: those
// the group lists, and the users whose primary group it is as far as NSS
// enumerates users or the gateway has seen them (principals.json in the
// state directory).
func (d *doctorRun) approverGroups() []doctor.Result {
	if d.gw.Notifications.Email.SMTP == "" || d.rbac == nil {
		return nil
	}
	var data struct {
		Approvers map[string][]string `json:"approvers"`
	}
	_ = json.Unmarshal(d.rbac, &data)
	var groups []string
	for _, rules := range data.Approvers {
		for _, rule := range rules {
			if g, ok := strings.CutPrefix(rule, "group:"); ok && !slices.Contains(groups, g) {
				groups = append(groups, g)
			}
		}
	}
	if len(groups) == 0 {
		return nil
	}
	slices.Sort(groups)
	seen, err := notify.LoadSeen(filepath.Join(d.gw.StateDir, "principals.json"))
	if err != nil {
		// Not root, or the gateway-admin server, which may not read the
		// state directory: whom the mail finds cannot be told.
		return []doctor.Result{{Check: "approver group " + strings.Join(groups, ", "), Status: doctor.Skip,
			Summary: "the users the gateway has seen cannot be read (mcp-gateway-admin doctor as root reads them): " + err.Error()}}
	}
	known := seen.Names()
	var out []doctor.Result
	for _, g := range groups {
		r := doctor.Result{Check: "approver group " + g}
		members, err := notify.GroupMembers(context.Background(), g, known)
		switch {
		case err != nil:
			r.Status, r.Summary = doctor.Warn, "group "+g+" not found: approval mail reaches nobody through it"
			r.Details = []string{"fix the group: rule in the approvers of the role data, or create the group"}
		case len(members) == 0:
			r.Status, r.Summary = doctor.Warn, "approval mail finds nobody in "+g
			r.Details = []string{"users whose primary group it is are found only if NSS enumerates users (SSSD, LDAP: enumerate = true)",
				"or once they used the gateway; name them as user: approvers instead"}
		default:
			r.Status, r.Summary = doctor.OK, fmt.Sprintf("approval mail reaches %d members of %s", len(members), g)
		}
		out = append(out, r)
	}
	return out
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
		r.Details = []string{strings.Join(unbound, ", "),
			"bind them to a role (Cockpit's Roles tab, or bindings in " + d.policyData + "), or remove them from " + group}
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
