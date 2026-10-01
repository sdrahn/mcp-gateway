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
	"github.com/sdrahn/mcp-gateway/internal/pseudo"
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
	// Privileged is set for privileged servers (docs/architecture.md,
	// section 5.7.1), which the gateway does not sandbox.
	Privileged bool `json:"privileged,omitempty"`
	// Annotations are the backend's tool annotations. They are untrusted
	// hints and must never grant access on their own.
	Annotations map[string]any `json:"annotations,omitempty"`
}

// Grant is a recorded human approval, as passed to policy.
type Grant struct {
	ID     string `json:"id"`
	Sub    string `json:"sub"`
	Issuer string `json:"iss,omitempty"`
	// UID is the principal's local uid, if any (for "own grant" checks).
	UID       *uint32        `json:"uid,omitempty"`
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
	Time      string              `json:"time"`
	Transport principal.Transport `json:"transport"`
	RequestID string              `json:"request_id,omitempty"`
	// DecisionID correlates OPA's decision log with the gateway's audit
	// record for the same enforcement.
	DecisionID         string         `json:"decision_id,omitempty"`
	ClientCapabilities map[string]any `json:"client_capabilities,omitempty"`
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

// Obligations are extra conditions attached to an allow; see
// obligations.go for their meaning and enforcement.
type Obligations struct {
	// RedactOutput are regular expressions; matches in any string of the
	// result are replaced with "[redacted]".
	RedactOutput []string `json:"redact_output,omitempty"`
	// MaxOutputBytes bounds the JSON size of the result (after redaction).
	MaxOutputBytes int64 `json:"max_output_bytes,omitempty"`
	// RateLimit are limits like "30/m" (per s, m or h), each applied per
	// principal and target. Policy may return a single string or a list.
	RateLimit StringList `json:"rate_limit,omitempty"`
	// ArgConstraints are regular expressions per argument (a string or a
	// list; all must match); the argument must be present and a string.
	ArgConstraints map[string]StringList `json:"arg_constraints,omitempty"`
	// Audit is "digest" (default) or "full" (arguments logged verbatim).
	Audit string `json:"audit,omitempty"`
	// Pseudonymize replaces personal or confidential values in the result
	// (and in sampling requests) by per-session pseudonyms.
	Pseudonymize *pseudo.Spec `json:"pseudonymize,omitempty"`
	// Reidentify names the arguments in which the gateway replaces
	// pseudonyms by the original values before forwarding the call.
	Reidentify StringList `json:"reidentify,omitempty"`
}

// Decision is the policy decision document (docs/architecture.md, section
// 6.3).
type Decision struct {
	Effect      Effect       `json:"effect"`
	Reason      string       `json:"reason,omitempty"`
	Ask         *AskSpec     `json:"ask,omitempty"`
	Obligations *Obligations `json:"obligations,omitempty"`
}

// Validate reports whether d is well-formed enough to be enforced,
// including its obligations.
func (d Decision) Validate() error {
	if d.Obligations != nil {
		if _, err := d.Obligations.Compile(); err != nil {
			return err
		}
	}
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
