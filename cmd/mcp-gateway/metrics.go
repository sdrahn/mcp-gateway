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

// metricsHandler serves GET /metrics and nothing else.
func metricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", metrics.ContentType)
		_ = metrics.Default.WriteText(w)
	})
	return mux
}

// serveMetrics serves the metrics over plain HTTP on addr
// (metrics.listen), without authentication.
func serveMetrics(log *slog.Logger, addr string) (func(), error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("metrics.listen: %w", err)
	}
	srv := &http.Server{Handler: metricsHandler(), ReadHeaderTimeout: 10 * time.Second}
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
