// Package pep is the policy enforcement point. It builds the policy input
// for a message, asks the policy decision point (OPA) for a decision, and
// applies it. It fails closed: any error, timeout or malformed decision
// results in a deny.
//
// See docs/architecture.md, sections 5.4 and 6.
package pep

import (
	"context"
	"fmt"

	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Effect is the outcome of a policy decision.
type Effect string

const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
	Ask   Effect = "ask"
)

// Channel is how an approval is obtained when the effect is Ask.
type Channel string

const (
	ChannelForm Channel = "form"
	ChannelURL  Channel = "url"
	ChannelOOB  Channel = "oob"
)

// Resource is the target of an action.
type Resource struct {
	Server string `json:"server"`
	// Kind is "tool", "resource" or "prompt".
	Kind string `json:"kind"`
	Name string `json:"name"`
	// Annotations are the backend's tool annotations. They are untrusted
	// hints and must never grant access on their own.
	Annotations map[string]any `json:"annotations,omitempty"`
}

// Grant is a recorded human approval, as passed to policy.
type Grant struct {
	ID        string         `json:"id"`
	Sub       string         `json:"sub"`
	Issuer    string         `json:"iss,omitempty"`
	Server    string         `json:"server"`
	Tool      string         `json:"tool"`
	ArgsMatch map[string]any `json:"args_match,omitempty"`
	// Scope is "once", "session" or "duration".
	Scope      string  `json:"scope"`
	SessionID  string  `json:"session_id,omitempty"`
	Expires    string  `json:"expires"`
	ApprovedBy string  `json:"approved_by"`
	Channel    Channel `json:"channel"`
}

// Context carries request metadata that is not part of the identity.
type Context struct {
	Time               string              `json:"time"`
	Transport          principal.Transport `json:"transport"`
	RequestID          string              `json:"request_id,omitempty"`
	ClientCapabilities map[string]any      `json:"client_capabilities,omitempty"`
}

// Input is the policy input document (docs/architecture.md, section 6.2).
type Input struct {
	Principal principal.Principal `json:"principal"`
	Action    string              `json:"action"`
	Resource  Resource            `json:"resource"`
	Args      map[string]any      `json:"args,omitempty"`
	Grants    []Grant             `json:"grants,omitempty"`
	Context   Context             `json:"context"`
}

// AskSpec describes how to obtain an approval.
type AskSpec struct {
	Channel Channel  `json:"channel"`
	Prompt  string   `json:"prompt"`
	Scopes  []string `json:"scopes,omitempty"`
	// Fallback is the channel used when the client cannot do Channel, or
	// "deny".
	Fallback string `json:"fallback,omitempty"`
}

// Obligations are extra conditions attached to an allow.
type Obligations struct {
	RedactOutput   []string          `json:"redact_output,omitempty"`
	MaxOutputBytes int64             `json:"max_output_bytes,omitempty"`
	RateLimit      string            `json:"rate_limit,omitempty"`
	ArgConstraints map[string]string `json:"arg_constraints,omitempty"`
	Audit          string            `json:"audit,omitempty"`
}

// Decision is the policy decision document (docs/architecture.md, section
// 6.3).
type Decision struct {
	Effect      Effect       `json:"effect"`
	Reason      string       `json:"reason,omitempty"`
	Ask         *AskSpec     `json:"ask,omitempty"`
	Obligations *Obligations `json:"obligations,omitempty"`
}

// Validate reports whether d is well-formed enough to be enforced.
func (d Decision) Validate() error {
	switch d.Effect {
	case Allow, Deny:
	case Ask:
		if d.Ask == nil {
			return fmt.Errorf("decision: effect %q without ask spec", d.Effect)
		}
		switch d.Ask.Channel {
		case ChannelForm, ChannelURL, ChannelOOB:
		default:
			return fmt.Errorf("decision: unknown ask channel %q", d.Ask.Channel)
		}
	default:
		return fmt.Errorf("decision: unknown effect %q", d.Effect)
	}
	return nil
}

// Decider is the policy decision point. Implementations: the OPA sidecar
// client, and later possibly embedded OPA.
type Decider interface {
	Decide(ctx context.Context, in Input) (Decision, error)
}

// Evaluate asks d for a decision and fails closed: an error or an invalid
// decision is turned into a deny.
func Evaluate(ctx context.Context, d Decider, in Input) Decision {
	dec, err := d.Decide(ctx, in)
	if err != nil {
		return Decision{Effect: Deny, Reason: "policy evaluation failed"}
	}
	if err := dec.Validate(); err != nil {
		return Decision{Effect: Deny, Reason: "invalid policy decision"}
	}
	return dec
}
