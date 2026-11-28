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
	"strconv"
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

// IsAlreadyExists reports whether err is the API server's answer to
// creating an object whose name is taken.
func IsAlreadyExists(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.Code == http.StatusConflict && e.Reason == "AlreadyExists"
}

// IsConflict reports whether err is the API server's answer to an update
// or a delete whose resource version is not the object's.
func IsConflict(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.Code == http.StatusConflict && e.Reason != "AlreadyExists"
}

// IsGone reports whether err says that a watch's resource version is
// too old: the collection must be listed again.
func IsGone(err error) bool {
	var e *APIError
	return errors.As(err, &e) && (e.Code == http.StatusGone || e.Reason == "Expired")
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

// Update replaces the object at path with obj (PUT): with obj's
// resourceVersion set, only if that is still the object's (IsConflict
// otherwise). The updated object is decoded into out (nil: drop it).
func (c *Client) Update(ctx context.Context, path string, obj, out any) error {
	return c.do(ctx, http.MethodPut, path, nil, obj, out)
}

// DeleteVersion deletes the object at path if its resource version is
// version (IsConflict otherwise); unlike Delete, one that is gone already
// is an error (IsNotFound): the caller learns whether it deleted it.
func (c *Client) DeleteVersion(ctx context.Context, path, version string) error {
	body := map[string]any{"kind": "DeleteOptions", "apiVersion": "v1",
		"preconditions": map[string]string{"resourceVersion": version}}
	return c.do(ctx, http.MethodDelete, path, nil, body, nil)
}

// WatchEvent is an event of a watch: its type (ADDED, MODIFIED, DELETED,
// BOOKMARK) and the object.
type WatchEvent struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

// Watch watches the collection at path with the labels of selector from
// resourceVersion on, calling fn for each event in order, until ctx ends,
// fn fails, or the API server ends the watch (after timeout, or
// earlier): then it returns nil, and the caller watches again from the
// last version it saw. A version too old to watch from is IsGone.
func (c *Client) Watch(ctx context.Context, path, selector, resourceVersion string, timeout time.Duration, fn func(WatchEvent) error) error {
	q := url.Values{"watch": {"1"}, "labelSelector": {selector}, "resourceVersion": {resourceVersion},
		"allowWatchBookmarks": {"true"}, "timeoutSeconds": {strconv.Itoa(int(timeout / time.Second))}}
	req, err := c.request(ctx, http.MethodGet, path, q, nil)
	if err != nil {
		return err
	}
	// The stream lasts longer than a request may (c.HTTP.Timeout).
	hc := &http.Client{Transport: c.HTTP.Transport}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("kubernetes: watch %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return apiError(resp.StatusCode, data)
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var ev WatchEvent
		if err := dec.Decode(&ev); err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("kubernetes: watch %s: %w", path, err)
		}
		if ev.Type == "ERROR" {
			var st struct {
				Code    int    `json:"code"`
				Reason  string `json:"reason"`
				Message string `json:"message"`
			}
			_ = json.Unmarshal(ev.Object, &st)
			return &APIError{Code: st.Code, Reason: st.Reason, Message: st.Message}
		}
		if err := fn(ev); err != nil {
			return err
		}
	}
}

// DeleteCollection deletes the objects of the collection at path with
// the labels of selector.
func (c *Client) DeleteCollection(ctx context.Context, path, selector string) error {
	body := map[string]any{"kind": "DeleteOptions", "apiVersion": "v1", "propagationPolicy": "Background"}
	return c.do(ctx, http.MethodDelete, path, url.Values{"labelSelector": {selector}}, body, nil)
}

// request is a request to the API server, with the token.
func (c *Client) request(ctx context.Context, method, path string, query url.Values, in any) (*http.Request, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	u := c.Server + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.TokenFile != "" {
		tok, err := os.ReadFile(c.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("kubernetes: token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	}
	return req, nil
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	req, err := c.request(ctx, method, path, query, in)
	if err != nil {
		return err
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
		return apiError(resp.StatusCode, data)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// apiError is the API server's answer with code and body (a Status).
func apiError(code int, data []byte) *APIError {
	var st struct {
		Reason  string `json:"reason"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(data, &st)
	if st.Message == "" {
		st.Message = strings.TrimSpace(string(data))
	}
	return &APIError{Code: code, Reason: st.Reason, Message: st.Message}
}
