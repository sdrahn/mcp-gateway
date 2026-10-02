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
	"sort"
	"strings"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/metrics"
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
	WhatIfPath       = "/v1/data/mcp/whatif/changes"
)

// whatIfTimeout bounds a "what changes?" query, which evaluates two
// decisions for every principal and resource.
const whatIfTimeout = 30 * time.Second

// WhatIfPrincipal is a principal to evaluate, with its label in the
// result ("user:alice", "group:dev").
type WhatIfPrincipal struct {
	Label     string              `json:"label"`
	Principal principal.Principal `json:"principal"`
}

// WhatIfInput is the input of the "what changes?" query (policy/mcp/whatif.rego).
type WhatIfInput struct {
	Principals []WhatIfPrincipal `json:"principals"`
	// Resources include kind "client" for requests MCP servers send.
	Resources []Resource      `json:"resources"`
	Proposed  json.RawMessage `json:"proposed"`
}

// Change is a decision that differs with the proposed role data.
type Change struct {
	Principal string `json:"principal"`
	Server    string `json:"server"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Before    string `json:"before"`
	After     string `json:"after"`
}

// WhatIf returns the decisions that change if the proposed role data
// replaces the current one.
func (o *OPA) WhatIf(ctx context.Context, in WhatIfInput) ([]Change, error) {
	var out []Change
	if err := o.queryWithin(ctx, whatIfTimeout, WhatIfPath, in, &out); err != nil {
		return nil, err
	}
	return out, nil
}

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

// VisibleInput is the input of data.mcp.filter.visible.
type VisibleInput struct {
	Principal principal.Principal `json:"principal"`
	Resources []Resource          `json:"resources"`
}

// Visible implements Filterer. On any error nothing is visible.
func (o *OPA) Visible(ctx context.Context, p principal.Principal, rs []Resource) ([]Resource, error) {
	in := VisibleInput{p, rs}
	var out []Resource
	if err := o.query(ctx, VisiblePath, in, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Fingerprint identifies the gateway's policy in OPA: a hash of the
// modules in packages below mcp, of data.mcp.rbac and of the roles the
// server setups ship (data.mcp.profiles). It changes when OPA
// reloads changed files, but not for other policies sharing the OPA.
func (o *OPA) Fingerprint(ctx context.Context) (string, error) {
	body, err := o.get(ctx, "/v1/policies")
	if err != nil {
		return "", err
	}
	var policies struct {
		Result []struct {
			ID  string `json:"id"`
			Raw string `json:"raw"`
			AST struct {
				Package struct {
					Path []struct {
						Value any `json:"value"`
					} `json:"path"`
				} `json:"package"`
			} `json:"ast"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &policies); err != nil {
		return "", fmt.Errorf("opa: policies: %w", err)
	}
	var modules []string
	for _, m := range policies.Result {
		// The package path starts with the data root: data.mcp.authz is
		// [data, "mcp", "authz"].
		if p := m.AST.Package.Path; len(p) > 1 && p[1].Value == "mcp" {
			modules = append(modules, m.ID+"\x00"+m.Raw)
		}
	}
	sort.Strings(modules)
	h := sha256.New()
	for _, m := range modules {
		h.Write([]byte(m))
		h.Write([]byte{0})
	}
	// Only the data: with decision logging on (as mcp-opa.service runs
	// OPA), the response also carries a new decision id each time.
	data, err := o.RoleData(ctx)
	if err != nil {
		return "", err
	}
	h.Write(data)
	h.Write([]byte{0})
	shipped, err := o.ShippedRoles(ctx)
	if err != nil {
		return "", err
	}
	h.Write(shipped)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// RoleData returns the role data OPA has loaded (data.mcp.rbac); empty if
// there is none.
func (o *OPA) RoleData(ctx context.Context) (json.RawMessage, error) {
	return o.data(ctx, "/v1/data/mcp/rbac", "role data")
}

// ShippedRoles returns the data of the server setup packages
// (data.mcp.profiles: setup name to {"roles": ...}); empty if there is
// none.
func (o *OPA) ShippedRoles(ctx context.Context) (json.RawMessage, error) {
	return o.data(ctx, "/v1/data/mcp/profiles", "shipped roles")
}

// data returns the result of a GET of a data document (empty if it is
// undefined), without the rest of the response.
func (o *OPA) data(ctx context.Context, path, what string) (json.RawMessage, error) {
	body, err := o.get(ctx, path)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("opa: %s: %w", what, err)
	}
	return resp.Result, nil
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
	return o.queryWithin(ctx, o.timeout, path, input, result)
}

func (o *OPA) queryWithin(ctx context.Context, timeout time.Duration, path string, input, result any) (err error) {
	query := strings.TrimPrefix(path, "/v1/data/")
	defer func(start time.Time) {
		metrics.OPADuration.Since(start, query)
		if err != nil {
			metrics.OPAErrors.Inc(query)
		}
	}(time.Now())
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	in, err := versioned(input)
	if err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		Input json.RawMessage `json:"input"`
	}{in})
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

// versioned returns input as JSON with "version" (InputVersion) added.
// Every input is a JSON object; none has a "version" of its own.
func versioned(input any) (json.RawMessage, error) {
	data, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	if len(data) < 2 || data[0] != '{' {
		return nil, fmt.Errorf("opa: policy input must be a JSON object, got %.20s", data)
	}
	v := fmt.Sprintf(`{"version":%d`, InputVersion)
	if string(data) == "{}" {
		return json.RawMessage(v + "}"), nil
	}
	return json.RawMessage(v + "," + string(data[1:])), nil
}
