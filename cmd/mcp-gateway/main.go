// Command mcp-gateway is the policy-enforcing MCP gateway daemon.
//
// Current scope (docs/architecture.md, section 11): local clients on the
// unix socket and remote clients over MCP Streamable HTTP with OAuth
// bearer tokens, per-server and aggregated endpoints, OPA decisions,
// form-mode approvals, backends as systemd transient units shared by a
// principal's sessions.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/sdrahn/mcp-gateway/internal/approvalpage"
	"github.com/sdrahn/mcp-gateway/internal/audit"
	"github.com/sdrahn/mcp-gateway/internal/authn"
	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	controlapi "github.com/sdrahn/mcp-gateway/internal/control"
	"github.com/sdrahn/mcp-gateway/internal/fswatch"
	"github.com/sdrahn/mcp-gateway/internal/metrics"
	"github.com/sdrahn/mcp-gateway/internal/notify"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/policydata"
	"github.com/sdrahn/mcp-gateway/internal/polkit"
	"github.com/sdrahn/mcp-gateway/internal/principal"
	"github.com/sdrahn/mcp-gateway/internal/router"
	"github.com/sdrahn/mcp-gateway/internal/signin"
	"github.com/sdrahn/mcp-gateway/internal/supervisor"
	"github.com/sdrahn/mcp-gateway/internal/transport"
	"github.com/sdrahn/mcp-gateway/internal/version"
	"github.com/sdrahn/mcp-gateway/internal/webhook"
)

// How often running containers and virtual machines are checked for
// category pairs that backend instances hold (supervisor.mcs_avoid). A
// container that takes an instance's pair shares it for at most this long;
// a scan reads one small file per process.
const mcsWatchInterval = 2 * time.Second

// The HTTPS listener's bounds: how long a request may take to send its
// body, and how long a connection may idle between requests.
const (
	httpBodyTimeout = 30 * time.Second
	httpIdleTimeout = 2 * time.Minute
)

func main() {
	configPath := flag.String("config", "", "path to the gateway configuration (default: "+
		config.DefaultConfigPath+", else "+config.DefaultVendorConfigPath+", else built-in defaults)")
	checkOnly := flag.Bool("check", false, "validate the configuration, the backend registry and the role data, then exit")
	checkData := flag.Bool("check-policy-data", false, "validate only the role data, then exit")
	policyData := flag.String("policy-data", policydata.DefaultPath,
		"role data to validate with -check and -check-policy-data (\"-\": standard input; empty: none)")
	flag.StringVar(&defaultPolicyData, "default-policy-data", policydata.DefaultData,
		"shipped default role data, in force while -policy-data's directory has none (empty: none)")
	flag.StringVar(&shippedPolicy, "shipped-policy", policydata.DefaultShippedDir,
		"shipped policy whose server setup roles bindings may name (empty: none)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	debug := flag.Bool("debug", false, "log debug messages")
	allowRoot := flag.Bool("allow-root", false, "run as root although the "+gatewayUser+" account exists "+
		"(the state files it creates are then root's; the service cannot read them)")
	flag.Usage = func() { usage(os.Stderr, flag.CommandLine) }
	if len(os.Args) > 1 && os.Args[1] == "help" {
		os.Exit(runHelp(os.Args[2:], os.Stdout, os.Stderr, flag.CommandLine))
	}
	flag.Parse()
	if flag.NArg() > 0 {
		// Not a command: without this, a mistyped one would start the
		// gateway.
		os.Exit(unknownCommand(flag.Arg(0), os.Stderr, flag.CommandLine))
	}

	if *showVersion {
		fmt.Println("mcp-gateway", version.Version)
		return
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if *checkData {
		if err := checkPolicyData(log, *policyData, true); err != nil {
			log.Error("role data invalid", "err", err)
			os.Exit(1)
		}
		return
	}
	if !*checkOnly {
		if err := refuseRoot(os.Geteuid(), *allowRoot, user.Lookup); err != nil {
			log.Error("fatal", "err", err)
			os.Exit(1)
		}
	}
	if err := run(log, *configPath, *checkOnly, *policyData); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// defaultPolicyData is the shipped default role data
// (-default-policy-data).
var defaultPolicyData string

// shippedPolicy is the shipped policy directory with the roles of the
// server setup packages (-shipped-policy).
var shippedPolicy string

// checkPolicyData validates the role data in force for path ("-":
// standard input; YAML or JSON) against its schema, printing each problem
// to standard error: for .../rbac/data.json or data.yaml, the data.yaml
// in that directory (policydata.InForce). A data.json without one is no
// longer read: an error (since 1.7). A missing file is an error only if
// required (the policy may come from a bundle).
func checkPolicyData(log *slog.Logger, path string, required bool) error {
	if path == "" {
		return nil
	}
	path, data, ignored, err := policydata.ReadOr(path, defaultPolicyData)
	for _, f := range ignored {
		log.Warn("role data ignored: another file is in force", "path", f, "in_force", path)
	}
	if errors.Is(err, fs.ErrNotExist) && !required {
		log.Info("no role data to check", "path", path)
		return nil
	}
	if err != nil {
		return err
	}
	var shipped map[string]string
	var problems []string
	if shippedPolicy != "" {
		if shipped, problems, err = policydata.ShippedRoles(shippedPolicy); err != nil {
			return err
		}
	}
	own, err := policydata.CheckWith(data, shipped)
	if err != nil {
		return err
	}
	problems = append(problems, own...)
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, p)
	}
	if len(problems) > 0 {
		if path == "-" {
			path = "standard input"
		}
		return fmt.Errorf("%s: %d problem(s)", path, len(problems))
	}
	log.Info("role data valid", "path", path)
	return nil
}

func run(log *slog.Logger, configPath string, checkOnly bool, policyData string) error {
	gw, used, err := config.Resolve(configPath)
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}
	if used == "" {
		used = "built-in defaults"
	}
	reloadFP := reloadFingerprint([]string{gw.VendorServersDir, gw.ServersDir}, reloadFiles(configPath, gw))
	backends, err := config.LoadBackends(gw.VendorServersDir, gw.ServersDir)
	if err != nil {
		return fmt.Errorf("loading backend registry: %w", err)
	}
	log.Info("configuration valid", "config", used, "drop_ins", strings.Join(gw.DropIns, ","), "socket", gw.Socket, "backends", len(backends))
	for _, w := range gw.Warnings {
		log.Warn(w, "config", used)
	}
	for _, name := range slices.Sorted(maps.Keys(backends)) {
		for _, w := range backends[name].Warnings {
			log.Warn(w, "server", name)
		}
		warnElevated(log, name, backends[name])
	}
	if err := config.CheckSignIn(gw, backends); err != nil {
		return err
	}
	if checkOnly {
		files, err := jsonFiles(policyData)
		if err != nil {
			log.Info("the policy files in JSON are not known", "err", err)
		}
		for _, f := range files {
			fmt.Fprintln(os.Stderr, policydata.JSONProblem(f))
		}
		if len(files) > 0 {
			return fmt.Errorf("%d file(s) in JSON in the policy: %w", len(files), policydata.ErrJSON)
		}
		if err := checkPolicyData(log, policyData, false); err != nil {
			return fmt.Errorf("role data: %w", err)
		}
		return nil
	}

	launcher, err := supervisor.NewLauncher(log, gw.Supervisor)
	if err != nil {
		return err
	}
	sd, _ := launcher.(*supervisor.Systemd)
	mcsAvoid := sd != nil && sd.SELinux && gw.Supervisor.MCSAvoid == "auto"
	if sd != nil && sd.SELinux {
		warnMissingSELinuxTypes(log, backends, supervisor.ContextValid)
	}

	// Before listening: a failed start leaves no socket behind.
	if err := checkStateOwnership(gw.StateDir, os.Geteuid()); err != nil {
		return err
	}
	l, err := transport.ListenUnix(gw.Socket, 0o660, gw.SocketGroup)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", gw.Socket, err)
	}
	log.Info("listening", "socket", gw.Socket, "version", version.Version)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup, stopHUP := notifyHUP() // systemctl reload: gateway.yaml and the server definitions
	defer stopHUP()

	if err := os.MkdirAll(gw.StateDir, 0o700); err != nil {
		return fmt.Errorf("state directory: %w", err)
	}
	auditLog, closeAudit, err := newAudit(log, gw)
	if err != nil {
		return err
	}
	defer closeAudit()

	control := gw.Approvals.ControlSocket != "-"
	opa := pep.NewOPA(gw.Policy.OPASocket, gw.Policy.Timeout)
	// While configuration in JSON is left over, which is no longer read,
	// every request is denied (step 38); not with bundles, when OPA does
	// not load the local policy.
	guard := &jsonGuard{log: log, policyData: policyData, bundles: func() (bool, error) {
		bctx, cancel := context.WithTimeout(ctx, gw.Policy.Timeout)
		defer cancel()
		b, err := opa.Bundles(bctx)
		return len(b) > 0, err
	}}
	guard.Blocked()
	b, err := broker.New(broker.Options{
		Timeout:     gw.ApprovalTimeout,
		GrantsFile:  filepath.Join(gw.StateDir, "grants.json"),
		PendingFile: filepath.Join(gw.StateDir, "pending.json"),
		URLTemplate: gw.ApprovalURLTemplate(),
		OOB:         control,
		Policy:      opa,
		Audit:       auditLog,
		Log:         log,
	})
	if err != nil {
		return err
	}
	// Mail is set up whether or not it is configured, so that a reload can
	// turn it on.
	mail, err := notify.NewEmail(gw.Notifications.Email, opa, log)
	if err != nil {
		return err
	}
	mail.URL = b.ApprovalURL
	// Local users seen, for approval mail to primary-group members where
	// NSS does not enumerate users.
	seen, err := notify.LoadSeen(filepath.Join(gw.StateDir, "principals.json"))
	if err != nil {
		log.Warn("known principals not read; starting with none", "err", err)
	}
	mail.Known = seen.Names
	// Primary-group members in SSSD's directories, through its InfoPipe
	// where SSSD lets the gateway ask.
	mail.InfoPipe = &notify.InfoPipe{}
	remember := func(name string) {
		if err := seen.Add(name); err != nil {
			log.Warn("principal not remembered", "name", name, "err", err)
		}
	}
	events, stopEvents := b.Subscribe()
	defer stopEvents()
	go mail.Run(ctx, events)
	if mail.Enabled() {
		log.Info("approval mail enabled", "smtp", gw.Notifications.Email.SMTP)
	}
	certs := &certStore{}
	if gw.HTTP.Listen != "" {
		if err := certs.load(gw.HTTP.CertFile, gw.HTTP.KeyFile); err != nil {
			return err
		}
	}
	if !control && gw.ApprovalURLTemplate() != "" {
		log.Warn("approvals.url_template is set but the control socket is disabled; url approvals cannot be decided")
	}
	page, err := newApprovalPage(log, gw, b, auditLog)
	if err != nil {
		return err
	}
	hooks, err := newWebhooks(log, gw, b, auditLog)
	if err != nil {
		return err
	}
	if hooks != nil {
		go hooks.Run(ctx)
	}
	signIns, err := newSignIns(log, gw, launcher, auditLog)
	if err != nil {
		return err
	}
	r := &router.Router{
		Seen:     remember,
		Backends: backends,
		Launcher: launcher,
		PDP:      pep.Guard{PDP: opa, Blocked: guard.Blocked},
		Broker:   b,
		Audit:    auditLog,
		Log:      log,

		IdleTimeout:      gw.Supervisor.IdleTimeout,
		StartTimeout:     gw.Supervisor.StartTimeout,
		WarmUp:           gw.Supervisor.WarmUp,
		ProgressInterval: gw.Approvals.ProgressInterval,

		MaxSessionsPerPrincipal:  gw.Limits.SessionsPerPrincipal,
		MaxInstancesPerPrincipal: gw.Limits.InstancesPerPrincipal,
		MaxInstances:             gw.Limits.Instances,
		ListTTL:                  gw.HTTP.ListTTL,
		RetryWait:                gw.Approvals.RetryWait,
		MaxRequestsPerPrincipal:  gw.Limits.RequestsPerPrincipal,
		MaxStreamsPerPrincipal:   gw.Limits.StreamsPerPrincipal,
		VaultIdle:                gw.Pseudonymize.VaultIdle,
		MaxTasksPerPrincipal:     gw.Limits.TasksPerPrincipal,
		MaxContextsPerPrincipal:  gw.Limits.ContextsPerPrincipal,
		TaskRetention:            gw.Tasks.Retention,
		TaskMaxResultBytes:       gw.Tasks.MaxResultBytes,
		MaxVersion:               gw.Agents.MaxVersion,
		NoRequestTimeout:         gw.Agents.NoRequestTimeout,
		NoWait:                   gw.Approvals.NoWait,
		ModernAgents:             true,
	}
	if signIns != nil {
		r.SignIns = signIns
		signIns.OnChange = r.SignInChanged
		// Tokens of servers whose definition lost sign_in, went away or
		// changed its url while the gateway was not running.
		signIns.Reconcile(backends)
	}

	reloader := &serverReloader{
		log: log, audit: auditLog, dirs: []string{gw.VendorServersDir, gw.ServersDir},
		load: func(dirs ...string) (map[string]*config.Backend, error) {
			next, err := config.LoadBackends(dirs...)
			if err == nil {
				err = config.CheckSignIn(gw, next)
			}
			return next, err
		}, set: r.SetBackends,
		loadConfig: func() (*config.Gateway, error) {
			next, _, err := config.Resolve(configPath)
			return next, err
		},
		applyConfig: func(next *config.Gateway) error {
			return applyConfig(log, next, gw, certs, mail, b, opa, r)
		},
		running:     gw,
		current:     gw,
		configFiles: func(c *config.Gateway) []string { return reloadFiles(configPath, c) },
		configDirs:  reloadDirs(configPath),
		loaded: func(next map[string]*config.Backend) {
			for _, name := range slices.Sorted(maps.Keys(next)) {
				warnElevated(log, name, next[name])
			}
			if sd != nil && sd.SELinux {
				warnMissingSELinuxTypes(log, next, supervisor.ContextValid)
			}
		},
	}

	registerGauges(r, b)
	if gw.Metrics.Listen != "" {
		stopMetrics, err := serveMetrics(log, gw.Metrics.Listen)
		if err != nil {
			return err
		}
		defer stopMetrics()
	}

	if control {
		cl, err := transport.ListenUnix(gw.Approvals.ControlSocket, 0o660, gw.SocketGroup)
		if err != nil {
			return fmt.Errorf("listening on %s: %w", gw.Approvals.ControlSocket, err)
		}
		log.Info("listening", "control", gw.Approvals.ControlSocket)
		identify := func(p transport.PeerCred) (broker.Approver, error) {
			a, err := controlapi.Identify(p)
			if err == nil {
				remember(a.Name)
			}
			return a, err
		}
		cs := &controlapi.Server{Broker: b, Identify: identify, Backends: r.CurrentBackends, ServersError: reloader.Err,
			ConfigError: reloader.ConfigErr, RestartNeeded: reloader.RestartNeeded, ConfigReloads: reloader.ConfigReloads, Instances: r, Tasks: r, Sessions: r, Policy: opa,
			Review: opa, Catalog: r, Log: log, RestartPending: restartPending, Metrics: metrics.Default}
		if signIns != nil {
			cs.SignIns = signIns
		}
		if gw.OwnApprovalsNeedPassword() {
			cs.OwnPassword = ownPassword(&polkit.Authority{})
		}
		go func() {
			if err := cs.Serve(ctx, cl); err != nil {
				log.Error("control API failed", "err", err)
			}
		}()
	}

	if mcsAvoid {
		go watchMCS(ctx, log, auditLog, sd, gw.Supervisor)
	}
	go watchUpdate(ctx, log)
	fsw, err := fswatch.New()
	if err != nil {
		log.Warn("changes to the configuration are noticed by polling only", "err", err)
	}
	defer func() { _ = fsw.Close() }()
	go reloader.watch(ctx, reloader.Interval, reloadFP, hup, fsw)

	// Clients learn about policy changes through list_changed: when a
	// local policy file is written, when OPA reports a bundle it
	// activated (policy.status_listen), and every policy.watch_interval.
	var opaStatus chan struct{}
	if gw.Policy.StatusListen != "" {
		opaStatus = make(chan struct{}, 1)
		stopStatus, err := serveOPAStatus(log, gw.Policy.StatusListen, opaStatus)
		if err != nil {
			stop()
			return err
		}
		defer stopStatus()
	}
	go r.WatchPolicy(ctx, reloader.Interval, opa.Fingerprint, func() {
		auditLog.Event("mcp-policy-change", true, map[string]string{"revision": bundleRevisions(ctx, opa)})
	}, mergeSignals(ctx, watchPolicyFiles(ctx, log, policyData, policydata.RenderDir, shippedPolicy), opaStatus))
	if revs := bundleRevisions(ctx, opa); revs != "" {
		log.Info("policy bundles", "revisions", revs)
	}

	// Serve returns after ctx ends and all backend instances are stopped;
	// always wait for it so no instance outlives the gateway.
	served := make(chan error, 1)
	go func() { served <- r.Serve(ctx, l) }()
	var httpErr error
	var httpErrs chan error
	stopHTTP := func() {}
	if gw.HTTP.Listen != "" {
		httpErrs = make(chan error, 1)
		if stopHTTP, err = serveHTTP(log, gw.HTTP, certs, r, signIns, page, hooks, httpErrs); err != nil {
			stop()
			return errors.Join(err, <-served)
		}
	}

	// Type=notify: ready once every listener is up.
	watchdog, err := daemon.SdWatchdogEnabled(false)
	if err != nil {
		log.Warn("systemd watchdog setting not understood", "err", err)
	}
	go notifySystemd(ctx, log, sdNotify, watchdog, func() string {
		sessions, instances := r.Stats()
		return statusLine(sessions, instances, b.PendingCount())
	})

	if httpErrs != nil {
		select {
		case httpErr = <-httpErrs:
		case <-ctx.Done():
		}
		stopHTTP()
		stop()
	}
	return errors.Join(httpErr, <-served)
}

// newSignIns sets up signing principals in to servers with sign_in: with
// the HTTP listener, which receives the callback (nil without).
func newSignIns(log *slog.Logger, gw *config.Gateway, launcher supervisor.Launcher, auditLog *audit.Logger) (*signin.Manager, error) {
	if gw.HTTP.Listen == "" || gw.RedirectURI() == "" {
		return nil, nil
	}
	dir := filepath.Join(gw.StateDir, "tokens")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("sign-in tokens: %w", err)
	}
	store, err := signin.OpenStore(dir)
	if err != nil {
		return nil, fmt.Errorf("sign-in tokens: %w", err)
	}
	// The access tokens handed to instances, until their units started:
	// next to the socket, /run/mcp-gateway/credentials.
	runDir := filepath.Join(filepath.Dir(gw.Socket), "credentials")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		log.Warn("sign-in: no runtime directory for tokens", "dir", runDir, "err", err)
	}
	m := &signin.Manager{Store: store, Launcher: launcher, Log: log, Audit: auditLog,
		RedirectURI: gw.RedirectURI(), RunDir: runDir, Timeout: gw.SignIn.Timeout}
	if strings.HasPrefix(gw.RedirectURI(), "https://") {
		m.ClientMetadataURL = strings.TrimSuffix(gw.RedirectURI(), "/callback") + "/client.json"
	}
	return m, nil
}

// serveHTTP starts the remote transport (MCP Streamable HTTP, OAuth
// resource server). The returned function ends all HTTP sessions and
// shuts the server down.
func serveHTTP(log *slog.Logger, cfg config.HTTP, certs *certStore, r *router.Router, signIns *signin.Manager,
	page *approvalpage.Page, hooks *webhook.Hooks, errc chan<- error) (func(), error) {
	tokens := authn.NewOAuth(cfg, nil)
	h, err := transport.NewHTTPHandler(transport.HTTPConfig{
		Resource:             cfg.Audience,
		AuthorizationServers: []string{cfg.Issuer},
		Scopes:               cfg.Scopes,
		AllowedOrigins:       cfg.AllowedOrigins,
		// Clients with a certificate can present certificate-bound tokens.
		CertificateBoundTokens: cfg.ClientAuth != "none",
		KnownServer:            func(name string) bool { return r.CurrentBackends()[name] != nil },
		SessionIdle:            cfg.SessionIdleTimeout,
		TokenExpired: func(p principal.Principal) {
			metrics.TokenExpiries.Inc()
			r.Audit.Event("mcp-token-expired", true, map[string]string{
				"principal": p.Sub, "transport": string(p.Transport), "session": p.SessionID,
			})
		},
		Request: r.ServeRequest,
		Log:     log,
	}, tokens, r.ServeClient)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := serverTLS(cfg)
	if err != nil {
		return nil, err
	}
	tlsConfig.GetCertificate = certs.getCertificate
	var handler http.Handler = h
	if signIns != nil || page != nil || hooks != nil {
		mux := http.NewServeMux()
		if signIns != nil {
			// The sign-in callback and client metadata, beside MCP.
			mux.Handle("/oauth/", signIns.Handler())
		}
		if page != nil {
			// The approval page, beside MCP; it validates ID tokens with
			// the key set the listener validates access tokens with.
			page.Tokens = tokens
			mux.Handle("/approvals/", page.Handler())
		}
		if hooks != nil {
			// The webhooks' signed callbacks.
			mux.Handle("/approvals/webhook/", hooks.Handler())
		}
		mux.Handle("/", h)
		handler = mux
	}
	// Unauthenticated clients reach the listener (the metadata, webhook
	// callbacks, the approval page's sign-in): headers and bodies have to
	// come in time, idle connections close, and the connections are
	// bounded; response streams (SSE) last as long as their token.
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           transport.BodyDeadline(handler, httpBodyTimeout),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       httpIdleTimeout,
		TLSConfig:         tlsConfig,
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	go func() {
		err := srv.ServeTLS(transport.LimitListener(ln, cfg.MaxConnections), "", "") // the certificate comes from certs
		if !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("http: %w", err)
		}
	}()
	log.Info("listening", "http", cfg.Listen, "resource", cfg.Audience)
	return func() {
		// Sessions first: open SSE streams only end with their session.
		h.Close()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}, nil
}

// newApprovalPage sets up the gateway's approval page (approvals.page),
// or returns nil without one. The client secret is read once, at start.
func newApprovalPage(log *slog.Logger, gw *config.Gateway, b *broker.Broker, auditLog *audit.Logger) (*approvalpage.Page, error) {
	pc := gw.Approvals.Page
	if !gw.PageEnabled() {
		return nil, nil
	}
	secret := ""
	if pc.ClientSecretFile != "" {
		warnExposed(log, "approvals.page.client_secret_file", pc.ClientSecretFile)
		data, err := os.ReadFile(pc.ClientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("approvals.page.client_secret_file: %w", err)
		}
		if secret = strings.TrimSpace(string(data)); secret == "" {
			return nil, fmt.Errorf("approvals.page.client_secret_file: %s is empty", pc.ClientSecretFile)
		}
	}
	pg := &approvalpage.Page{
		Issuer: gw.HTTP.Issuer, Origin: gw.PageOrigin(),
		ClientID: pc.ClientID, ClientSecret: secret, DeviceClientID: pc.DeviceClientID,
		Scopes: pc.Scopes, SessionTTL: pc.SessionTTL, Broker: b, Audit: auditLog, Log: log,
		// The gateway reaches the identity provider directly, as for its
		// key set.
		Client: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}},
	}
	// The system's logo and name, as Cockpit's login page shows them.
	pg.Branding = approvalpage.LoadBranding(approvalpage.CockpitBranding, approvalpage.OSRelease)
	log.Info("approval page", "url", pg.Origin+"/approvals/", "client_id", pc.ClientID, "redirect_uri", pg.RedirectURI(),
		"os", pg.Branding.OSName, "logo", pg.Branding.Logo != nil)
	return pg, nil
}

// newWebhooks sets up the approval webhooks (approvals.webhooks), or
// returns nil without any. Their secrets are read once, at start. The
// callbacks come to the HTTP listener; without it the webhooks only post.
func newWebhooks(log *slog.Logger, gw *config.Gateway, b *broker.Broker, auditLog *audit.Logger) (*webhook.Hooks, error) {
	if len(gw.Approvals.Webhooks) == 0 {
		return nil, nil
	}
	h := &webhook.Hooks{Broker: b, Audit: auditLog, Log: log,
		// Receivers are reached directly, as the identity provider is.
		Client: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}},
	}
	origin := gw.PageOrigin()
	if gw.HTTP.Listen != "" && origin != "" {
		h.Callback = origin + "/approvals/webhook/{name}"
	}
	if u, err := url.Parse(origin); err == nil && u.Hostname() != "" {
		h.Gateway = u.Hostname()
	} else if host, err := os.Hostname(); err == nil {
		h.Gateway = host
	}
	for i, w := range gw.Approvals.Webhooks {
		warnExposed(log, fmt.Sprintf("approvals.webhooks[%d].secret_file", i), w.SecretFile)
		data, err := os.ReadFile(w.SecretFile)
		if err != nil {
			return nil, fmt.Errorf("approvals.webhooks[%d].secret_file: %w", i, err)
		}
		secret := strings.TrimSpace(string(data))
		if len(secret) < config.MinWebhookSecret {
			return nil, fmt.Errorf("approvals.webhooks[%d].secret_file: %s holds %d characters, fewer than %d", i, w.SecretFile, len(secret), config.MinWebhookSecret)
		}
		h.Hooks = append(h.Hooks, webhook.Hook{Name: w.Name, URL: w.URL, Secret: []byte(secret),
			IncludeArgs: w.IncludeArgs, Servers: w.Servers, LocalAccounts: w.LocalAccounts})
		cb := strings.ReplaceAll(h.Callback, "{name}", w.Name)
		if cb == "" {
			cb = "none (no HTTP listener)"
		}
		log.Info("approval webhook", "name", w.Name, "url", w.URL, "callback", cb, "include_args", w.IncludeArgs)
	}
	return h, nil
}

// warnExposed warns when others may read a secret file (the doctor fails
// then); the gateway starts all the same.
func warnExposed(log *slog.Logger, key, path string) {
	if mode, err := config.ExposedSecret(path); err == nil && mode != "" {
		log.Warn(key+": others may read the secret (mode "+mode+"); chmod 0640 and make a new secret", "file", path)
	}
}

// startExe is the program file the gateway was started from (nil if
// unknown), to notice when an update replaces it.
var startExe = programFile()

// programFile stats the gateway's program file by the path it was started
// with (the unit uses /usr/bin/mcp-gateway), not through /proc/self/exe,
// which the gateway's SELinux domain need not read.
func programFile() os.FileInfo {
	path := os.Args[0]
	if !filepath.IsAbs(path) {
		var err error
		if path, err = exec.LookPath(path); err != nil {
			return nil
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil
	}
	return fi
}

// restartPending reports whether the program file was replaced since the
// start: the package does not restart the gateway on update, since an
// update made through a privileged server would wait for itself
// (docs/architecture.md, section 5.7.1).
func restartPending() bool {
	return replaced(startExe, programFile())
}

// replaced reports whether now is another file than start (or gone).
func replaced(start, now os.FileInfo) bool {
	return start != nil && (now == nil || !os.SameFile(start, now))
}

// watchUpdate logs once when the program was updated.
func watchUpdate(ctx context.Context, log *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if restartPending() {
			log.Warn("mcp-gateway was updated; restart mcp-gateway.service to use the new version (calls to privileged servers are waited for)")
			return
		}
	}
}

// newAudit sets up the audit trail: JSON records on stderr (journald),
// argument digests keyed with the per-installation key in the state
// directory, and security-relevant events to the kernel audit subsystem.
func newAudit(log *slog.Logger, gw *config.Gateway) (*audit.Logger, func(), error) {
	key, err := audit.LoadKey(filepath.Join(gw.StateDir, "audit.key"))
	if err != nil {
		return nil, nil, fmt.Errorf("audit key: %w", err)
	}
	opts := audit.Options{Key: key}
	closeFn := func() {}
	if gw.Audit.Kernel != "off" {
		nl, err := audit.OpenNetlink()
		switch {
		case err == nil:
			opts.Kernel = nl
			closeFn = func() { _ = nl.Close() }
			log.Info("kernel audit enabled")
		case gw.Audit.Kernel == "on":
			return nil, nil, fmt.Errorf("kernel audit: %w", err)
		default:
			log.Warn("kernel audit not available", "err", err)
		}
	}
	return audit.New(os.Stderr, opts), closeFn, nil
}

// bundleRevisions describes the activated policy bundles as
// "name=revision,…" (empty with directory-loaded policy or on errors).
func bundleRevisions(ctx context.Context, opa *pep.OPA) string {
	bundles, err := opa.Bundles(ctx)
	if err != nil {
		return ""
	}
	var out []string
	for name, rev := range bundles {
		out = append(out, name+"="+rev)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// serverTLS returns the TLS configuration of the remote transport, with
// client certificate verification (mTLS) as configured.
func serverTLS(cfg config.HTTP) (*tls.Config, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.ClientAuth == "none" {
		return c, nil
	}
	pem, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("http.client_ca_file: %w", err)
	}
	c.ClientCAs = x509.NewCertPool()
	if !c.ClientCAs.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("http.client_ca_file: no certificates in %s", cfg.ClientCAFile)
	}
	c.ClientAuth = tls.VerifyClientCertIfGiven
	if cfg.ClientAuth == "required" {
		c.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return c, nil
}

// watchMCS coordinates MCS category pairs with podman and libvirt
// (docs/architecture.md, section 5.8): it warns about libvirt daemons
// whose range overlaps the gateway's, and replaces backend instances whose
// pair a container or virtual machine took after them.
func watchMCS(ctx context.Context, log *slog.Logger, auditLog *audit.Logger, sd *supervisor.Systemd, cfg config.Supervisor) {
	lo, hi, _ := cfg.MCSCategories()
	warned := map[int]bool{}
	check := func(scan supervisor.MCSScan) {
		for _, d := range scan.Overlapping(lo, hi) {
			if !warned[d.PID] {
				warned[d.PID] = true
				log.Warn("libvirt picks MCS categories from the gateway's range; confine it with a drop-in from /usr/share/mcp-gateway/mcs",
					"pid", d.PID, "context", d.Context, "mcs_range", cfg.MCSRange)
			}
		}
		for _, c := range sd.Collisions(scan) {
			log.Warn("MCS pair taken by another workload; stopping the instance", "instance", c.Instance,
				"pair", c.Pair, "pid", c.Foreign.PID, "context", c.Foreign.Context)
			auditLog.Event("mcp-mcs-collision", false, map[string]string{
				"instance": c.Instance, "pair": c.Pair, "foreign_pid": strconv.Itoa(c.Foreign.PID), "foreign_context": c.Foreign.Context,
			})
		}
	}
	check(supervisor.ScanMCS("/proc"))
	supervisor.WatchMCS(ctx, "/proc", mcsWatchInterval, check)
}

// warnElevated logs a server with rights beyond the sandbox: privileged,
// or with capabilities.
func warnElevated(log *slog.Logger, name string, b *config.Backend) {
	switch {
	case b.Privileged:
		log.Warn("privileged server: runs as root without sandbox; every call is decided by policy and approval", "server", name)
	case len(b.Sandbox.Capabilities) > 0:
		log.Warn("server with capabilities: runs in the sandbox with "+strings.Join(b.Sandbox.Capabilities, ", ")+"; every call is decided by policy and approval as for a privileged server", "server", name)
	}
}

// warnMissingSELinuxTypes logs servers whose selinux_type the loaded
// policy does not know: their instances would fail to start with only
// systemd's "Failed to change SELinux context" to go by. The gateway
// still starts, for the other servers.
func warnMissingSELinuxTypes(log *slog.Logger, backends map[string]*config.Backend, valid func(string) (bool, error)) {
	missing, err := supervisor.MissingSELinuxTypes(backends, valid)
	if err != nil {
		log.Info("cannot check the servers' SELinux types", "err", err)
		return
	}
	types := make([]string, 0, len(missing))
	for t := range missing {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		log.Warn("selinux_type is not in the loaded SELinux policy; install its module, or instances of these servers fail to start",
			"selinux_type", t, "servers", strings.Join(missing[t], ","))
	}
}

// ownPassword asks polkit to authenticate the user of the process peer
// (auth_self, never kept: polkit asks every time) before they approve
// their own request p (roadmap step 40). The dialog names the call.
func ownPassword(auth *polkit.Authority) func(context.Context, transport.PeerCred, broker.Pending) error {
	return func(ctx context.Context, peer transport.PeerCred, p broker.Pending) error {
		ok, err := auth.Check(ctx, peer.PID, peer.UID, polkit.DecideOwn, map[string]string{
			"call": p.Server + "/" + p.Name, "id": p.ID})
		switch {
		case errors.Is(err, polkit.ErrNoAgent):
			return errors.New("no one to ask for it (no terminal or desktop session for polkit to ask in)")
		case err != nil:
			return err
		case !ok:
			return errors.New("polkit did not authenticate you")
		}
		return nil
	}
}
