package main

import (
	"context"
	"log/slog"
	"path/filepath"

	"github.com/sdrahn/mcp-gateway/internal/fswatch"
)

// watchPolicyFiles tells, on the returned channel, when a file of the
// local policy changed: the role data's directories (policyData is
// .../policy/rbac/data.json; OPA loads .../policy as a whole) and the
// shipped policy, with their subdirectories, the trees mcp-opa.service
// runs with --watch. Policy from a bundle server is not on disk: it is
// noticed by polling only. Directories that cannot be watched are logged
// once while they stay so. It returns nil without inotify.
func watchPolicyFiles(ctx context.Context, log *slog.Logger, policyData, shipped string) <-chan struct{} {
	fsw, err := fswatch.New()
	if err != nil {
		log.Warn("policy changes are noticed by polling only", "err", err)
		return nil
	}
	roots := []string{filepath.Dir(filepath.Dir(policyData)), filepath.Dir(policyData)}
	if shipped != "" {
		roots = append(roots, shipped)
	}
	unwatched := map[string]bool{}
	set := func() {
		dirs := fswatch.Tree(roots...)
		failed := fsw.Set(dirs)
		for _, d := range dirs {
			err, bad := failed[d]
			switch {
			case bad && !unwatched[d]:
				unwatched[d] = true
				log.Info("policy changes in a directory are noticed by polling only", "dir", d, "err", err)
			case !bad:
				delete(unwatched, d)
			}
		}
	}
	set()
	out := make(chan struct{}, 1)
	go func() {
		defer func() { _ = fsw.Close() }()
		for {
			select {
			case <-ctx.Done():
				return
			case <-fsw.Events():
				set() // a directory may have been created
				select {
				case out <- struct{}{}:
				default:
				}
			}
		}
	}()
	return out
}
