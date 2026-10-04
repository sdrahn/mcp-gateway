package main

import (
	"crypto/tls"
	"fmt"
	"sync/atomic"
)

// certStore holds the TLS certificate of the remote transport; a reload
// of the configuration puts a renewed one in force for new connections.
type certStore struct {
	cert atomic.Pointer[tls.Certificate]
}

// load reads the certificate and key; on an error the one in force stays.
func (c *certStore) load(certFile, keyFile string) error {
	cert, err := loadCert(certFile, keyFile)
	if err != nil {
		return err
	}
	c.cert.Store(cert)
	return nil
}

func loadCert(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("http.cert_file, http.key_file: %w", err)
	}
	return &cert, nil
}

// getCertificate is the tls.Config's GetCertificate.
func (c *certStore) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return c.cert.Load(), nil
}
