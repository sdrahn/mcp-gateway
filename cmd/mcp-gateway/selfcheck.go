package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/authn"
	"github.com/sdrahn/mcp-gateway/internal/config"
	controlapi "github.com/sdrahn/mcp-gateway/internal/control"
	"github.com/sdrahn/mcp-gateway/internal/doctor"
	"github.com/sdrahn/mcp-gateway/internal/httpsetup"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/store"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
)

// The doctor in the gateway (docs/architecture.md, section 5.12.7,
// roadmap step 48): in container mode there is no host to run
// mcp-gateway-admin doctor on, so the gateway runs the checks that apply
// to it itself, at the start, after each reload and on request (POST
// /v1/doctor), and keeps the results for the console and doctor
// --gateway: its configuration, the policy engine, its listener's
// certificate, the identity providers' key sets, the approval page's
// client and the webhooks, the servers' URLs, the state volume and the
// Kubernetes API.

// selfCheckTimeout bounds a run; serverDialTimeout each server's
// connection.
const (
	selfCheckTimeout  = 60 * time.Second
	serverDialTimeout = 5 * time.Second
)

// decider is the policy engine (pep.OPA).
type decider interface {
	Decide(ctx context.Context, in pep.Input) (pep.Decision, error)
}

// selfCheck runs the checks and keeps the last report.
type selfCheck struct {
	log      *slog.Logger
	gw       *config.Gateway
	backends func() map[string]*config.Backend
	reloader *serverReloader
	opa      decider
	tokens   *authn.OAuth           // nil without the HTTP listener
	kube     *supervisor.Kubernetes // nil without the Kubernetes launcher
	// shared is a collection of the shared store (nil without one).
	shared store.Collection
	// ready, if set, tells whether the policy engine answers (pep.OPA.
	// Health): the run at the start waits for it, as OPA starts beside
	// the gateway in the pod.
	ready func(context.Context) error
	// replica names this replica of several in its reports.
	replica string
	// dial connects to a server's address (net.Dialer by default).
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	now  func() time.Time

	run sync.Mutex // one run at a time
	mu  sync.Mutex
	rep *controlapi.DoctorReport
}

// Report implements controlapi.Doctor.
func (c *selfCheck) Report(ctx context.Context) controlapi.DoctorReport {
	c.mu.Lock()
	rep := c.rep
	c.mu.Unlock()
	if rep != nil {
		return *rep
	}
	return c.check(ctx, "request")
}

// Run implements controlapi.Doctor.
func (c *selfCheck) Run(ctx context.Context) controlapi.DoctorReport {
	return c.check(ctx, "request")
}

// background runs the checks for trigger without waiting for them, and
// logs what fails or warns.
func (c *selfCheck) background(trigger string) {
	go func() {
		if trigger == "start" {
			c.waitReady(context.Background())
		}
		rep := c.check(context.Background(), trigger)
		for _, r := range rep.Results {
			switch r.Status {
			case doctor.Fail:
				c.log.Error("doctor: "+r.Summary, "check", r.ID, "subject", r.Subject, "trigger", trigger)
			case doctor.Warn:
				c.log.Warn("doctor: "+r.Summary, "check", r.ID, "subject", r.Subject, "trigger", trigger)
			}
		}
	}()
}

// startWait bounds how long the run at the start waits for the policy
// engine; readyPoll is how often it asks.
var (
	startWait = 30 * time.Second
	readyPoll = time.Second
)

// waitReady waits until the policy engine answers, or startWait has
// passed: then the checks run and say what fails.
func (c *selfCheck) waitReady(ctx context.Context) {
	if c.ready == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, startWait)
	defer cancel()
	for c.ready(ctx) != nil {
		select {
		case <-ctx.Done():
			return
		case <-time.After(readyPoll):
		}
	}
}

func (c *selfCheck) check(ctx context.Context, trigger string) controlapi.DoctorReport {
	c.run.Lock()
	defer c.run.Unlock()
	ctx, cancel := context.WithTimeout(ctx, selfCheckTimeout)
	defer cancel()
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	rs := c.results(ctx, trigger)
	doctor.Identify(rs)
	rep := controlapi.DoctorReport{Checked: now().UTC(), Trigger: trigger, Replica: c.replica, Results: rs}
	c.mu.Lock()
	c.rep = &rep
	c.mu.Unlock()
	return rep
}

func (c *selfCheck) results(ctx context.Context, trigger string) []doctor.Result {
	var rs []doctor.Result
	add := func(r ...doctor.Result) { rs = append(rs, r...) }
	add(c.configuration())
	add(c.policy(ctx))
	if c.gw.HTTP.Listen != "" {
		acct, err := ownAccount()
		if err != nil {
			add(doctor.Result{Check: "TLS", Status: doctor.Skip, Summary: err.Error()})
		} else {
			add(doctor.TLS(c.gw.HTTP, acct, nil, time.Now())...)
		}
	}
	add(c.issuers(ctx)...)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	if c.gw.PageEnabled() {
		// The page signs in with the sign-in issuer, which may be the
		// first of http.issuers.
		gw := *c.gw
		gw.HTTP.Issuer = gw.HTTP.SignInIssuer()
		add(httpsetup.ApprovalPage(ctx, &gw, client, true))
	}
	// A webhook's check posts a ping to its receiver: on request only,
	// not at every start and reload.
	if trigger == "request" {
		add(doctor.Webhooks(ctx, c.gw, client, true)...)
	} else {
		for _, w := range c.gw.Approvals.Webhooks {
			add(doctor.Result{Check: "webhook " + w.Name, Status: doctor.Skip,
				Summary: "checked on request only (it posts a ping to the receiver): Check again, or mcp-gateway-admin doctor --gateway"})
		}
	}
	add(c.servers(ctx)...)
	add(c.stateVolume())
	if c.shared != nil {
		add(c.sharedStore(ctx))
	}
	if c.kube != nil {
		add(c.kubernetes(ctx))
	}
	return rs
}

// configuration: whether the last reload of gateway.yaml and of the
// server definitions was taken, and the keys waiting for a restart.
func (c *selfCheck) configuration() doctor.Result {
	r := doctor.Result{Check: "configuration", Status: doctor.OK, Summary: "gateway.yaml and the server definitions are in force"}
	if c.reloader == nil {
		return r
	}
	var details []string
	if e := c.reloader.ConfigErr(); e != "" {
		details = append(details, "gateway.yaml: "+e)
	}
	if e := c.reloader.Err(); e != "" {
		details = append(details, "server definitions: "+e)
	}
	if len(details) > 0 {
		r.Status, r.Summary = doctor.Fail, "the last change was refused; the gateway runs with what it had"
		r.Details = append(details, "fix the files where they are kept (the ConfigMaps, or /etc/mcp-gateway): the gateway reloads them")
		return r
	}
	if keys := c.reloader.RestartNeeded(); len(keys) > 0 {
		r.Status, r.Summary = doctor.Warn, "keys changed that take effect at the next start: "+strings.Join(keys, ", ")
		r.Details = []string{"roll the Deployment (the chart does with a change of gateway.yaml), or restart the service"}
	}
	// What gateway.yaml says that works but should be changed: deprecated
	// keys, a cluster's issuer as the one people sign in with (#412).
	if c.gw != nil && len(c.gw.Warnings) > 0 {
		if r.Status == doctor.OK {
			r.Status, r.Summary = doctor.Warn, "gateway.yaml is in force, with warnings"
		}
		r.Details = append(r.Details, c.gw.Warnings...)
	}
	return r
}

// policy: OPA decides, as mcp-gateway-admin doctor checks it.
func (c *selfCheck) policy(ctx context.Context) doctor.Result {
	r := doctor.Result{Check: "policy"}
	dec, err := c.opa.Decide(ctx, pep.Input{
		Principal: principal.Principal{Sub: "mcp-doctor", Transport: principal.TransportInternal},
		Action:    "tools.call",
		Resource:  pep.Resource{Server: "mcp-doctor", Kind: "tool", Name: "probe"},
	})
	switch {
	case err != nil:
		r.Status, r.Summary = doctor.Fail, "OPA does not decide: "+err.Error()
		r.Details = []string{"every request is denied while this fails; see the opa container's log"}
	case dec.Validate() != nil:
		r.Status, r.Summary = doctor.Fail, "OPA's decision is invalid: "+dec.Validate().Error()
	default:
		r.Status, r.Summary = doctor.OK, fmt.Sprintf("OPA decides (%s for an unknown principal)", dec.Effect)
	}
	return r
}

// issuers: each identity provider's key set, as the listener fetches it.
func (c *selfCheck) issuers(ctx context.Context) []doctor.Result {
	if c.tokens == nil {
		return nil
	}
	var rs []doctor.Result
	for _, st := range c.tokens.CheckIssuers(ctx) {
		r := doctor.Result{Check: "identity provider " + st.Issuer}
		switch {
		case st.Err != nil && st.Keys == 0:
			r.Status, r.Summary = doctor.Fail, "no key set: "+st.Err.Error()
			r.Details = []string{"tokens of this issuer are refused; check its URL, ca_file and token_file, and the network policy"}
		case st.Err != nil:
			r.Status, r.Summary = doctor.Warn, fmt.Sprintf("the key set was not fetched again (%v); the %d keys fetched before stay", st.Err, st.Keys)
		default:
			r.Status, r.Summary = doctor.OK, fmt.Sprintf("key set with %d key%s", st.Keys, map[bool]string{true: "s"}[st.Keys != 1])
		}
		rs = append(rs, r)
	}
	return rs
}

// servers: a connection to each server's URL (or its proxy), as its
// connector makes it.
func (c *selfCheck) servers(ctx context.Context) []doctor.Result {
	backends := c.backends()
	names := make([]string, 0, len(backends))
	for n, b := range backends {
		if b.URL != "" {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	dial := c.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	var rs []doctor.Result
	for _, n := range names {
		b := backends[n]
		r := doctor.Result{Check: "server " + n}
		target, via := b.URL, ""
		if b.Proxy != "" {
			target, via = b.Proxy, " through its proxy"
		}
		addr, err := hostPort(target)
		if err != nil {
			r.Status, r.Summary = doctor.Fail, err.Error()
			rs = append(rs, r)
			continue
		}
		dctx, cancel := context.WithTimeout(ctx, serverDialTimeout)
		conn, err := dial(dctx, "tcp", addr)
		cancel()
		if err != nil {
			r.Status, r.Summary = doctor.Fail, fmt.Sprintf("%s%s does not answer: %v", addr, via, err)
			r.Details = []string{"calls to this server fail; check its url, its host name, and what the network lets the gateway reach (in a cluster: the Service and the gateway pod's NetworkPolicy)"}
		} else {
			_ = conn.Close()
			r.Status, r.Summary = doctor.OK, addr+via+" accepts connections"
		}
		rs = append(rs, r)
	}
	return rs
}

// hostPort is the address a URL connects to.
func hostPort(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%q is not a URL", raw)
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

// stateVolume: the gateway can write its state directory.
func (c *selfCheck) stateVolume() doctor.Result {
	r := doctor.Result{Check: "state volume", Subject: c.gw.StateDir}
	f, err := os.CreateTemp(c.gw.StateDir, ".doctor-")
	if err != nil {
		r.Status, r.Summary = doctor.Fail, fmt.Sprintf("%s is not writable: %v", c.gw.StateDir, err)
		r.Details = []string{"grants, sign-in tokens and the audit key are not kept; mount a volume the gateway's account may write (fsGroup)"}
		return r
	}
	_ = f.Close()
	_ = os.Remove(f.Name())
	r.Status, r.Summary = doctor.OK, c.gw.StateDir+" is writable"
	return r
}

// sharedStore: the gateway reaches the shared store and may list its
// records (replication.store: kubernetes).
func (c *selfCheck) sharedStore(ctx context.Context) doctor.Result {
	ns := c.gw.Replication.Namespace
	r := doctor.Result{Check: "shared store", Subject: ns}
	recs, _, err := c.shared.List(ctx)
	if err != nil {
		r.Status, r.Summary = doctor.Fail, "the API server does not list the gateway's records in "+ns+": "+err.Error()
		r.Details = []string{"grants, approvals and sign-ins are not kept; check the gateway's Role for Secrets in that namespace (get, list, watch, create, update, delete)"}
		return r
	}
	r.Status, r.Summary = doctor.OK, fmt.Sprintf("the API server answers: %d keys in %s", len(recs), ns)
	return r
}

// kubernetes: the launcher reaches the API server and may list the
// instances' pods.
func (c *selfCheck) kubernetes(ctx context.Context) doctor.Result {
	r := doctor.Result{Check: "kubernetes", Subject: c.kube.Options.Namespace}
	n, err := c.kube.Check(ctx)
	if err != nil {
		r.Status, r.Summary = doctor.Fail, "the API server does not list the instances' pods in "+c.kube.Options.Namespace+": "+err.Error()
		r.Details = []string{"stdio servers do not start; check the gateway's Role and RoleBinding in that namespace"}
		return r
	}
	r.Status, r.Summary = doctor.OK, fmt.Sprintf("the API server answers: %d instance pods in %s", n, c.kube.Options.Namespace)
	return r
}

// ownAccount is the account the gateway runs as.
func ownAccount() (doctor.Account, error) {
	acct := doctor.Account{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	acct.Name = strconv.Itoa(os.Getuid())
	if u, err := user.LookupId(acct.Name); err == nil {
		acct.Name = u.Username
	}
	gids, err := os.Getgroups()
	if err != nil {
		return acct, err
	}
	for _, g := range gids {
		acct.Groups = append(acct.Groups, uint32(g))
	}
	return acct, nil
}
