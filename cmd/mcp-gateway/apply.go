package main

import (
	"log/slog"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/notify"
	"github.com/sdrahn/mcp-gateway/internal/pep"
	"github.com/sdrahn/mcp-gateway/internal/router"
)

// applyConfig puts the reloadable keys of next (config.Reloadable) in
// force; running is the configuration the gateway started with. What
// can fail (the TLS certificate, the SMTP password) is read first: on an
// error nothing changes.
func applyConfig(log *slog.Logger, next, running *config.Gateway, certs *certStore, mail *notify.Email,
	b *broker.Broker, opa *pep.OPA, r *router.Router) error {
	var cert = certs.cert.Load()
	if running.HTTP.Listen != "" && next.HTTP.Listen != "" { // otherwise a restart is due anyway
		c, err := loadCert(next.HTTP.CertFile, next.HTTP.KeyFile)
		if err != nil {
			return err
		}
		cert = c
	}
	if err := mail.Configure(next.Notifications.Email); err != nil {
		return err
	}
	certs.cert.Store(cert)
	b.SetApprovals(next.ApprovalTimeout, next.Approvals.URLTemplate)
	opa.SetTimeout(next.Policy.Timeout)
	r.SetSettings(router.Settings{
		IdleTimeout:              next.Supervisor.IdleTimeout,
		ProgressInterval:         next.Approvals.ProgressInterval,
		MaxSessionsPerPrincipal:  next.Limits.SessionsPerPrincipal,
		MaxInstancesPerPrincipal: next.Limits.InstancesPerPrincipal,
		MaxInstances:             next.Limits.Instances,
		ListTTL:                  next.HTTP.ListTTL,
		RetryWait:                next.Approvals.RetryWait,
		MaxRequestsPerPrincipal:  next.Limits.RequestsPerPrincipal,
		MaxStreamsPerPrincipal:   next.Limits.StreamsPerPrincipal,
		VaultIdle:                next.Pseudonymize.VaultIdle,
		MaxVersion:               next.Agents.MaxVersion,
		NoRequestTimeout:         next.Agents.NoRequestTimeout,
	})
	if running.Approvals.ControlSocket == "-" && next.Approvals.URLTemplate != "" {
		log.Warn("approvals.url_template is set but the control socket is disabled; url approvals cannot be decided")
	}
	return nil
}

// reloadFiles lists the files besides servers.d whose change triggers a
// reload: gateway.yaml (the explicit one, or both places it is looked
// for), the TLS certificate and key, the SMTP password.
func reloadFiles(explicit string, c *config.Gateway) []string {
	files := []string{config.DefaultConfigPath, config.DefaultVendorConfigPath}
	if explicit != "" {
		files = []string{explicit}
	}
	if c == nil {
		return files
	}
	if c.HTTP.Listen != "" {
		files = append(files, c.HTTP.CertFile, c.HTTP.KeyFile)
	}
	if f := c.Notifications.Email.PasswordFile; f != "" {
		files = append(files, f)
	}
	return files
}
