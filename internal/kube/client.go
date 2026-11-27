package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Client speaks the Kubernetes API's REST interface as the gateway's
// ServiceAccount: its token read anew for each request (the kubelet
// renews a projected token), the cluster's CA.
type Client struct {
	// Server is the API server's URL (https://kubernetes.default.svc).
	Server string
	// TokenFile holds the bearer token.
	TokenFile string
	HTTP      *http.Client
}

// NewClient returns a client of server, with the token in tokenFile and
// the CA certificates in caFile (empty: the system's).
func NewClient(server, tokenFile, caFile string) (*Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // the API server is reached directly
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("kubernetes: ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("kubernetes: ca_file: %s has no PEM certificate", caFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &Client{Server: strings.TrimSuffix(server, "/"), TokenFile: tokenFile,
		HTTP: &http.Client{Transport: tr, Timeout: 30 * time.Second}}, nil
}

// APIError is an answer of the API server's that is not a success.
type APIError struct {
	Code    int
	Reason  string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("kubernetes: %d %s: %s", e.Code, e.Reason, e.Message)
}

// IsNotFound reports whether err is the API server's 404.
func IsNotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.Code == http.StatusNotFound
}

// Paths of the objects the launcher creates.
func PodsPath(ns string) string { return "/api/v1/namespaces/" + url.PathEscape(ns) + "/pods" }
func SecretsPath(ns string) string {
	return "/api/v1/namespaces/" + url.PathEscape(ns) + "/secrets"
}
func NetworkPoliciesPath(ns string) string {
	return "/apis/networking.k8s.io/v1/namespaces/" + url.PathEscape(ns) + "/networkpolicies"
}

// Create posts obj to the collection at path, and decodes the created
// object into out (nil: drop it).
func (c *Client) Create(ctx context.Context, path string, obj, out any) error {
	return c.do(ctx, http.MethodPost, path, nil, obj, out)
}

// Get decodes the object at path into out.
func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, nil, out)
}

// List decodes the objects of the collection at path with the labels of
// selector ("k=v,k2=v2") into out.
func (c *Client) List(ctx context.Context, path, selector string, out any) error {
	return c.do(ctx, http.MethodGet, path, url.Values{"labelSelector": {selector}}, nil, out)
}

// Delete deletes the object at path, its dependents in the background;
// one that is gone already is no error.
func (c *Client) Delete(ctx context.Context, path string, gracePeriod int64) error {
	body := map[string]any{"kind": "DeleteOptions", "apiVersion": "v1", "propagationPolicy": "Background",
		"gracePeriodSeconds": gracePeriod}
	err := c.do(ctx, http.MethodDelete, path, nil, body, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}

// DeleteCollection deletes the objects of the collection at path with
// the labels of selector.
func (c *Client) DeleteCollection(ctx context.Context, path, selector string) error {
	body := map[string]any{"kind": "DeleteOptions", "apiVersion": "v1", "propagationPolicy": "Background"}
	return c.do(ctx, http.MethodDelete, path, url.Values{"labelSelector": {selector}}, body, nil)
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	u := c.Server + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.TokenFile != "" {
		tok, err := os.ReadFile(c.TokenFile)
		if err != nil {
			return fmt.Errorf("kubernetes: token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("kubernetes: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var st struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &st)
		if st.Message == "" {
			st.Message = strings.TrimSpace(string(data))
		}
		return &APIError{Code: resp.StatusCode, Reason: st.Reason, Message: st.Message}
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}
