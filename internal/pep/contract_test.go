package pep

import (
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/contract"
)

// The policy documents' fields (docs/architecture.md, sections 6.2 and
// 6.3, decision D10). Every input also has "version" (InputVersion),
// which the OPA client adds.
func TestContract(t *testing.T) {
	for file, v := range map[string]any{
		"input.txt":          Input{},
		"decision.txt":       Decision{},
		"visible-input.txt":  VisibleInput{},
		"visible-result.txt": []Resource{},
		"hints-result.txt":   []Hint{},
		"whatif-input.txt":   WhatIfInput{},
		"whatif-result.txt":  []Change{},
	} {
		t.Run(file, func(t *testing.T) { contract.Check(t, "testdata/contract/"+file, v) })
	}
}
