package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/metrics"
	"github.com/sdrahn/mcp-gateway/internal/router"
	"github.com/sdrahn/mcp-gateway/internal/version"
)

// registerGauges adds the gauges read from the running gateway.
func registerGauges(r *router.Router, b *broker.Broker) {
	metrics.Default.Register(
		metrics.NewGauge("mcp_gateway_sessions", "Client sessions.", func() float64 {
			s, _ := r.Stats()
			return float64(s)
		}),
		metrics.NewGauge("mcp_gateway_instances", "Running backend instances.", func() float64 {
			_, i := r.Stats()
			return float64(i)
		}),
		metrics.NewGauge("mcp_gateway_approvals_pending", "Approvals waiting for a decision.", func() float64 {
			return float64(b.PendingCount())
		}),
		metrics.NewGauge("mcp_gateway_restart_pending", "1 when the program was updated and the gateway not yet restarted.", func() float64 {
			if restartPending() {
				return 1
			}
			return 0
		}),
		metrics.NewGauge("mcp_gateway_build_info", "The gateway's version.", func() float64 { return 1 }, "version", version.Version),
	)
}

// metricsHandler serves GET /metrics, and the probes of a container
// platform (docs/architecture.md, section 5.12.7): GET /healthz, the
// process serves; GET /readyz, it can decide, as OPA answers (ready).
// A refused reload does not make the gateway unready: it serves what it
// ran.
func metricsHandler(ready func(context.Context) error) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", metrics.ContentType)
		_ = metrics.Default.WriteText(w)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if ready != nil {
			if err := ready(ctx); err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = fmt.Fprintln(w, "not ready: the policy engine:", err)
				return
			}
		}
		_, _ = fmt.Fprintln(w, "ready")
	})
	return mux
}

// serveMetrics serves the metrics and the probes over plain HTTP on addr
// (metrics.listen), without authentication.
func serveMetrics(log *slog.Logger, addr string, ready func(context.Context) error) (func(), error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("metrics.listen: %w", err)
	}
	srv := &http.Server{Handler: metricsHandler(ready), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(l); !errors.Is(err, http.ErrServerClosed) {
			log.Error("metrics listener failed", "err", err)
		}
	}()
	log.Info("listening", "metrics", l.Addr().String())
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}, nil
}
