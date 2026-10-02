package control

import (
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/contract"
	"github.com/sdrahn/mcp-gateway/internal/pep"
)

// The control API's requests and responses (/v1; docs/architecture.md,
// decision D10, and the user guide's reference).
func TestContract(t *testing.T) {
	for file, v := range map[string]any{
		"whoami.txt":           broker.Approver{},
		"status.txt":           statusResponse{},
		"approvals.txt":        []broker.Pending{},
		"approval-decide.txt":  resolveRequest{},
		"approval-decided.txt": pep.Grant{},
		"grants.txt":           []pep.Grant{},
		"servers.txt":          []serverInfo{},
		"policy.txt":           policyResponse{},
		"whatif.txt":           whatIfResponse{},
		"events.txt":           approvalEvent{},
		"error.txt":            errorResponse{},
	} {
		t.Run(file, func(t *testing.T) { contract.Check(t, "testdata/contract/"+file, v) })
	}
}
