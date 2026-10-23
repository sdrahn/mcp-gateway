package main

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/policydata"
)

// jsonFiles returns the files of the local policy in JSON that 1.6 read as
// configuration (policydata.JSONFiles), which are no longer read:
// policyData is .../policy/rbac/data.json, OPA loads .../policy. The
// gateway only lists the directories; it need not read the files.
func jsonFiles(policyData string) ([]string, error) {
	if policyData == "" || policyData == "-" {
		return nil, nil
	}
	rbac := filepath.Dir(policyData)
	return policydata.JSONFiles(filepath.Dir(rbac), rbac)
}

// jsonCheckInterval is how long a jsonGuard's finding holds: a request
// after it looks again.
const jsonCheckInterval = 2 * time.Second

// A jsonGuard reports, for pep.Guard, why the policy is blocked: the files
// in JSON left over in the local policy (step 38), each an error, logged
// when found and when gone. While OPA runs on bundles (bundles reports
// true) the local policy is not loaded, and nothing blocks.
type jsonGuard struct {
	log        *slog.Logger
	policyData string
	bundles    func() (bool, error) // nil: none

	mu      sync.Mutex
	checked time.Time
	files   []string
	reason  string
}

// Blocked returns "" while no configuration in JSON is left over, else a
// reason naming the first file and the command that converts it.
func (g *jsonGuard) Blocked() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if time.Since(g.checked) < jsonCheckInterval {
		return g.reason
	}
	g.checked = time.Now()
	files, err := jsonFiles(g.policyData)
	if err == nil && len(files) > 0 && g.bundles != nil {
		var inBundle bool
		if inBundle, err = g.bundles(); inBundle {
			files = nil
		}
	}
	if err != nil {
		// Not known (a directory that cannot be listed, OPA not
		// answering): as before. Without OPA nothing is allowed anyway.
		g.log.Debug("the policy files in JSON are not known", "err", err)
		return g.reason
	}
	if slices.Equal(files, g.files) {
		return g.reason
	}
	g.files = files
	g.reason = ""
	for _, f := range files {
		g.log.Error(policydata.ErrJSON.Error()+"; every request is denied until it is converted",
			"path", f, "convert", policydata.ConvertCommand(f))
	}
	switch len(files) {
	case 0:
		g.log.Info("no configuration in JSON is left over; the policy decides again")
	case 1:
		g.reason = policydata.JSONProblem(files[0])
	default:
		g.reason = fmt.Sprintf("%s (and %d more files in JSON)", policydata.JSONProblem(files[0]), len(files)-1)
	}
	return g.reason
}
