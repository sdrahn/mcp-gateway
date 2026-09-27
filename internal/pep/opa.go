package pep

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Filterer decides which resources a principal may see in discovery
// results.
type Filterer interface {
	Visible(ctx context.Context, p principal.Principal, rs []Resource) ([]Resource, error)
}

// PDP is the full policy decision point interface used by the router.
type PDP interface {
	Decider
	Filterer
}

// Policy paths queried in OPA.
const (
	DecisionPath     = "/v1/data/mcp/authz/decision"
	VisiblePath      = "/v1/data/mcp/filter/visible"
	ApproveAllowPath = "/v1/data/mcp/approvals/allow"
	ManageGrantPath  = "/v1/data/mcp/approvals/manage_grant"
)

// OPA queries an OPA server over its REST API on a unix socket.
type OPA struct {
	client  *http.Client
	timeout time.Duration
}

// NewOPA returns a client for the OPA server listening on socket.
func NewOPA(socket string, timeout time.Duration) *OPA {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:    16,
		IdleConnTimeout: time.Minute,
	}
	return &OPA{client: &http.Client{Transport: tr}, timeout: timeout}
}

// Decide implements Decider. A missing result (undefined decision) is an
// error, which Evaluate turns into a deny.
func (o *OPA) Decide(ctx context.Context, in Input) (Decision, error) {
	var d Decision
	if err := o.query(ctx, DecisionPath, in, &d); err != nil {
		return Decision{}, err
	}
	return d, nil
}

// Visible implements Filterer. On any error nothing is visible.
func (o *OPA) Visible(ctx context.Context, p principal.Principal, rs []Resource) ([]Resource, error) {
	in := struct {
		Principal principal.Principal `json:"principal"`
		Resources []Resource          `json:"resources"`
	}{p, rs}
	var out []Resource
	if err := o.query(ctx, VisiblePath, in, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Fingerprint identifies the policy OPA has loaded: a hash of its
// modules and of data.rbac. It changes when OPA reloads changed files.
func (o *OPA) Fingerprint(ctx context.Context) (string, error) {
	h := sha256.New()
	for _, path := range []string{"/v1/policies", "/v1/data/rbac"} {
		body, err := o.get(ctx, path)
		if err != nil {
			return "", err
		}
		h.Write(body)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Bundles returns the revision of each activated policy bundle, by
// bundle name; empty when OPA loads the policy from directories.
func (o *OPA) Bundles(ctx context.Context) (map[string]string, error) {
	body, err := o.get(ctx, "/v1/data/system/bundles")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Result map[string]struct {
			Manifest struct {
				Revision string `json:"revision"`
			} `json:"manifest"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("opa: bundles: %w", err)
	}
	out := make(map[string]string, len(resp.Result))
	for name, b := range resp.Result {
		out[name] = b.Manifest.Revision
	}
	return out, nil
}

func (o *OPA) get(ctx context.Context, path string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://opa"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("opa: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("opa: GET %s: %s", path, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

// Bool queries a boolean rule; an undefined or non-boolean result is an
// error.
// Strings evaluates a policy rule that yields a set or list of strings
// (undefined yields none).
func (o *OPA) Strings(ctx context.Context, path string, input any) ([]string, error) {
	var out []string
	if err := o.query(ctx, path, input, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (o *OPA) Bool(ctx context.Context, path string, input any) (bool, error) {
	var b bool
	if err := o.query(ctx, path, input, &b); err != nil {
		return false, err
	}
	return b, nil
}

func (o *OPA) query(ctx context.Context, path string, input, result any) error {
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	body, err := json.Marshal(struct {
		Input any `json:"input"`
	}{input})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://opa"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("opa: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("opa: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("opa: %s: %s", resp.Status, bytes.TrimSpace(data))
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("opa: %w", err)
	}
	if len(envelope.Result) == 0 {
		return errors.New("opa: undefined result for " + path)
	}
	return json.Unmarshal(envelope.Result, result)
}
