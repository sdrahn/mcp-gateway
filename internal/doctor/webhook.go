package doctor

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/webhook"
)

// Webhooks checks each approval webhook (approvals.webhooks): its secret
// file, and that the receiver takes a signed "ping" post as the gateway
// sends it (client: directly, not through a proxy). Reading the secret
// needs root; without it the check is skipped. A webhook without the
// HTTP listener only posts: decisions cannot come back, a warning.
func Webhooks(ctx context.Context, gw *config.Gateway, client *http.Client, root bool) []Result {
	var rs []Result
	hooks := &webhook.Hooks{Client: client, Gateway: "doctor"}
	for _, w := range gw.Approvals.Webhooks {
		r := Result{Check: "webhook " + w.Name}
		if !root {
			r.Status, r.Summary = Skip, "reading "+w.SecretFile+" needs root: run mcp-gateway-admin doctor as root"
			rs = append(rs, r)
			continue
		}
		data, err := os.ReadFile(w.SecretFile)
		secret := strings.TrimSpace(string(data))
		switch {
		case err != nil:
			r.Status, r.Summary, r.Details = Fail, "secret_file: "+err.Error(), []string{"the gateway does not start without it"}
		case len(secret) < config.MinWebhookSecret:
			r.Status, r.Summary = Fail, fmt.Sprintf("secret_file: %s holds %d characters, fewer than %d", w.SecretFile, len(secret), config.MinWebhookSecret)
			r.Details = []string{"the gateway does not start with it; make one with: openssl rand -hex 32"}
		default:
			if err := hooks.Ping(ctx, &webhook.Hook{Name: w.Name, URL: w.URL, Secret: []byte(secret)}); err != nil {
				r.Status, r.Summary = Fail, "the receiver does not take a signed post: "+err.Error()
				r.Details = []string{"approvals are posted to " + w.URL + "; under SELinux the gateway reaches HTTP ports only (80, 443, 8080, 8443, …)"}
			} else if gw.HTTP.Listen == "" || gw.PageOrigin() == "" {
				r.Status, r.Summary = Warn, "the receiver takes signed posts, but decisions cannot come back: no HTTP listener (http.listen, http.audience) for the callback"
			} else {
				r.Status, r.Summary = OK, "the receiver takes signed posts; decisions come back to "+gw.PageOrigin()+"/approvals/webhook/"+w.Name
			}
		}
		rs = append(rs, r)
	}
	return rs
}
