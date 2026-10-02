package broker

import (
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/contract"
)

// The input of the approver rules (data.mcp.approvals; docs/architecture.md,
// decision D10), which the OPA client gives "version" too.
func TestContract(t *testing.T) {
	contract.Check(t, "testdata/contract/approver-input.txt", ApproverInput{})
}
