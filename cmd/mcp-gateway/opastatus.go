package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// maxStatusReport bounds an OPA status report the gateway reads.
const maxStatusReport = 4 << 20

// opaStatusHandler takes OPA's status reports (the status plugin POSTs
// them to <service url>/status, one whenever a bundle is activated or
// fails). Each one has the policy watcher check the policy at once
// (notify): the report itself is not trusted, anyone on the host may send
// one, and a check only reads OPA. A bundle that failed is logged.
func opaStatusHandler(log *slog.Logger, notify chan<- struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxStatusReport+1))
		if err != nil || len(body) > maxStatusReport {
			http.Error(w, "status report too large or unreadable", http.StatusRequestEntityTooLarge)
			return
		}
		select {
		case notify <- struct{}{}:
		default: // a check is due already
		}
		var report struct {
			Bundles map[string]struct {
				ActiveRevision string `json:"active_revision"`
				Code           string `json:"code"`
				Message        string `json:"message"`
			} `json:"bundles"`
		}
		if json.Unmarshal(body, &report) == nil {
			var active, failed []string
			for name, b := range report.Bundles {
				active = append(active, name+"="+b.ActiveRevision)
				if b.Code != "" {
					failed = append(failed, fmt.Sprintf("%s: %s %s", name, b.Code, b.Message))
				}
			}
			sort.Strings(active)
			sort.Strings(failed)
			if len(failed) > 0 {
				log.Warn("OPA reports a policy bundle it could not activate", "errors", strings.Join(failed, "; "), "active", strings.Join(active, ","))
			} else {
				log.Debug("OPA status report", "bundles", strings.Join(active, ","))
			}
		}
		w.WriteHeader(http.StatusOK)
	})
}

// serveOPAStatus serves opaStatusHandler on addr (policy.status_listen).
func serveOPAStatus(log *slog.Logger, addr string, notify chan<- struct{}) (func(), error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("policy.status_listen: %w", err)
	}
	srv := &http.Server{Handler: opaStatusHandler(log, notify), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute}
	go func() {
		if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
			log.Error("OPA status listener failed", "err", err)
		}
	}()
	log.Info("listening", "opa_status", l.Addr().String())
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}, nil
}

// mergeSignals returns a channel that receives when any of chans does
// (nil ones are left out), until ctx ends.
func mergeSignals(ctx context.Context, chans ...<-chan struct{}) <-chan struct{} {
	out := make(chan struct{}, 1)
	for _, c := range chans {
		if c == nil {
			continue
		}
		go func(c <-chan struct{}) {
			for {
				select {
				case <-ctx.Done():
					return
				case _, ok := <-c:
					if !ok {
						return
					}
					select {
					case out <- struct{}{}:
					default:
					}
				}
			}
		}(c)
	}
	return out
}
