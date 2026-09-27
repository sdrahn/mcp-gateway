package pep

import (
	"bytes"
	"context"
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
	DecisionPath = "/v1/data/mcp/authz/decision"
	VisiblePath  = "/v1/data/mcp/filter/visible"
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
