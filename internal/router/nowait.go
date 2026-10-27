package router

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/pep"
)

// Agents that show nothing while a call waits (Kit) leave their user with
// an agent that seems stuck while an out-of-band approval waits for an
// approver nobody told. For the clients approvals.no_wait names, such an
// approval is not waited for: the call is answered at once with a tool
// error the model passes on, naming the approval and where it is decided,
// and the agent's next attempt finds the decision (docs/architecture.md,
// section 11, step 39 stage A; D21).

// noWait reports whether the session's client is one whose out-of-band
// approvals are not waited for (approvals.no_wait).
func (s *Session) noWait() bool {
	st := s.r.settings()
	if slices.Contains(st.NoWait, "*") {
		return true
	}
	name := strings.ToLower(s.snapshotPrincipal().Client.Name)
	return name != "" && slices.Contains(st.NoWait, name)
}

// askedElsewhere parks the out-of-band approval of in for the agent's next
// attempt and returns the decision the call is answered with now: ask,
// with what the agent's user needs to know as the reason. A denial made
// while no call waited answers the attempt after it.
func (s *Session) askedElsewhere(ctx context.Context, t *callTarget, in pep.Input, ask pep.AskSpec) pep.Decision {
	if s.r.Broker.TakeDenial(in) {
		return pep.Decision{Effect: pep.Deny, Reason: "declined by an approver"}
	}
	id, expires := s.r.Broker.ParkFor(in, ask, pep.ChannelOOB, broker.NoWaitTTL)
	s.r.Broker.NotifyOOB(requestElicitor{s, requestOf(ctx)}, in, id)
	return pep.Decision{Effect: pep.Ask, Reason: approvalNeeded(t.resource.Server, t.resource.Name, id, expires,
		gatewayHost(), s.r.settings().RemoteApprovals, s.r.Broker.ApprovalURL(id))}
}

// approvalNeeded is the tool error of a call whose approval is not
// waited for: what waits, until when, and how the user gets it decided:
// the command on the gateway's host, on other hosts (remote, the URL
// "approvals --gateway" takes, if any) and the approval page (url, if
// any). The model is asked to pass the commands on as plain text: an
// agent's display may drop a code block (Kit showed "Command line on
// host:" and nothing after it).
func approvalNeeded(server, tool, id string, expires time.Time, host, remote, url string) string {
	where := fmt.Sprintf("an approver runs \"mcp-gateway-admin approvals approve %s\" on %s", id, host)
	if remote != "" {
		where += fmt.Sprintf("; on another host, \"mcp-gateway-admin approvals approve %s --gateway %s\" "+
			"(signed in once with \"mcp-gateway-admin approvals login --gateway %s\")", id, remote, remote)
	}
	if url != "" {
		where += "; or decides at " + url
	}
	return fmt.Sprintf("approval needed: %s/%s waits for an approver's decision (approval %s, open until %s). "+
		"Tell the user, giving each command in full as plain text, not in a code block: %s. "+
		"Then call the tool again with the same arguments; it runs once approved.",
		server, tool, id, expires.UTC().Format("15:04 UTC"), where)
}

// gatewayHost is the host name the approval is decided on.
var gatewayHost = sync.OnceValue(func() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "the gateway's host"
})
