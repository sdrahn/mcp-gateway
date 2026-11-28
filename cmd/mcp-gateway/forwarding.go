package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/authn"
	"github.com/sdrahn/mcp-gateway/internal/cluster"
	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/replicas"
	"github.com/sdrahn/mcp-gateway/internal/router"
	"github.com/sdrahn/mcp-gateway/internal/transport"
)

// forwarding is what several replicas need to send each principal's
// requests to its owner (replication.listen; docs/architecture.md,
// section 5.12.5): the replicas, the principals' Leases, the peer
// listener's TLS (the replicas' certificate, required of clients too) and
// the transport to the peers.
type forwarding struct {
	members   *replicas.Members
	owners    *replicas.Owners
	listen    string
	serverTLS *tls.Config
	transport http.RoundTripper
	// internal serves what the replicas ask each other (cluster.Prefix).
	internal http.Handler
}

// forwarding sets up the forwarding between replicas, nil without it
// (one replica, or none on the store). The principals' Leases are kept
// until stop, then given up.
func (s *sharedStore) forwarding(log *slog.Logger, gw *config.Gateway, r *router.Router, tokens *authn.OAuth) (*forwarding, error) {
	if s == nil || s.members == nil || !gw.Replication.Forwarding() || tokens == nil {
		return nil, nil
	}
	rep := gw.Replication.WithDefaults()
	cert, err := tls.LoadX509KeyPair(rep.PeerCertFile, rep.PeerKeyFile)
	if err != nil {
		return nil, fmt.Errorf("replication.peer_cert_file: %w", err)
	}
	pem, err := os.ReadFile(rep.PeerCAFile)
	if err != nil {
		return nil, fmt.Errorf("replication.peer_ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("replication.peer_ca_file: no certificate in %s", rep.PeerCAFile)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // the peers are reached directly
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool,
		ServerName: rep.PeerServerName}
	tr.ResponseHeaderTimeout = 0 // a call may wait for its approval
	o := &replicas.Owners{Client: s.client, Namespace: s.namespace, Members: s.members, Idle: gw.Supervisor.IdleTimeout,
		Busy: func() map[string]bool { return busyPrincipals(r) }}
	done := make(chan struct{})
	go func() {
		o.Run(s.ctx)
		close(done)
	}()
	s.owned = done
	return &forwarding{members: s.members, owners: o, listen: rep.Listen, transport: tr,
		serverTLS: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: pool,
			ClientAuth: tls.RequireAndVerifyClientCert}}, nil
}

// busyPrincipals are the principals with instances, sessions or tasks
// here, by the key of their Lease.
func busyPrincipals(r *router.Router) map[string]bool {
	out := map[string]bool{}
	for _, s := range r.Sessions() {
		out[string(s.Transport)+"\x00"+s.Issuer+"\x00"+s.Sub] = true
	}
	for _, i := range r.Instances() {
		out[string(i.Transport)+"\x00"+i.Issuer+"\x00"+i.Sub] = true
	}
	for _, t := range r.Tasks() {
		if t.Status == "working" || t.Status == "input_required" {
			out[string(t.Transport)+"\x00"+t.Issuer+"\x00"+t.Sub] = true
		}
	}
	return out
}

// serve starts the peer listener with f's PeerHandler; the returned
// function stops it.
func (fw *forwarding) serve(log *slog.Logger, f *replicas.Forwarder, errc chan<- error) (func(), error) {
	srv := &http.Server{
		Addr: fw.listen,
		Handler: transport.BodyDeadline(&replicas.PeerHandler{Forwarder: f, Internal: fw.internal, InternalPrefix: cluster.Prefix},
			httpBodyTimeout),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       httpIdleTimeout,
		TLSConfig:         fw.serverTLS,
	}
	ln, err := net.Listen("tcp", fw.listen)
	if err != nil {
		return nil, fmt.Errorf("replication.listen: %w", err)
	}
	go func() {
		if err := srv.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
			errc <- fmt.Errorf("replication.listen: %w", err)
		}
	}()
	log.Info("replicas: peer listener", "listen", fw.listen, "address", fw.members.Address)
	return func() { _ = srv.Close() }, nil
}
