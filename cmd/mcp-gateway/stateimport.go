package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/signin"
	"github.com/sdrahn/mcp-gateway/internal/store"
)

// importedKey is the record of the keys' collection that says the files
// were imported.
const importedKey = "imported"

// importState copies the files of state_dir into the shared store at the
// first start with it (docs/architecture.md, section 5.12.5): a gateway
// moved from its volume to the store keeps its grants, pending approvals,
// notices, reviews, clients seen, sign-in tokens and the key of its
// audit's digests. Once done (a record of the keys' collection says so),
// the files are not read again; a record the store has already is kept.
func importState(ctx context.Context, log *slog.Logger, gw *config.Gateway, s *sharedStore) error {
	if s == nil {
		return nil
	}
	keys, err := s.collection("keys")
	if err != nil {
		return err
	}
	recs, _, err := keys.List(ctx)
	if err != nil {
		return fmt.Errorf("shared store: %w", err)
	}
	for _, r := range recs {
		if r.Name == importedKey {
			return nil
		}
	}
	copied := map[string]int{}
	for file, name := range map[string]string{"grants.json": "grants", "pending.json": "pending",
		"notices.json": "notices", "reviews.json": "reviews", "clients.json": "clients"} {
		c, err := s.collection(name)
		if err != nil {
			return err
		}
		n, err := importList(ctx, filepath.Join(gw.StateDir, file), c)
		if err != nil {
			return fmt.Errorf("shared store: importing %s: %w", file, err)
		}
		copied[file] = n
	}
	if key, err := os.ReadFile(filepath.Join(gw.StateDir, "audit.key")); err == nil && len(key) != 32 {
		log.Warn("shared store: audit.key not imported: not 32 bytes; digests of earlier records will not compare", "bytes", len(key))
	} else if err == nil {
		switch _, err := keys.Create(ctx, "audit", key); {
		case errors.Is(err, store.ErrExists):
			log.Warn("shared store: audit.key not imported: the store has an audit key of its own")
		case err != nil:
			return fmt.Errorf("shared store: importing audit.key: %w", err)
		default:
			copied["audit.key"] = 1
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("shared store: audit.key: %w", err)
	}
	tokens, err := s.collection("tokens")
	if err != nil {
		return err
	}
	if n, err := signin.ImportFiles(ctx, filepath.Join(gw.StateDir, "tokens"), tokens, keys); err != nil {
		log.Warn("shared store: sign-in tokens not imported", "err", err)
	} else {
		copied["tokens"] = n
	}
	if _, err := keys.Create(ctx, importedKey, []byte(time.Now().UTC().Format(time.RFC3339))); err != nil && !errors.Is(err, store.ErrExists) {
		return fmt.Errorf("shared store: %w", err)
	}
	log.Info("shared store: the files of state_dir imported", "records", copied)
	return nil
}

// importList copies the items of a JSON list (each with an "id") into c,
// a record each named by its id. A file not there copies nothing.
func importList(ctx context.Context, path string, c store.Collection) (int, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var list []json.RawMessage
	if err := json.Unmarshal(data, &list); err != nil {
		return 0, err
	}
	n := 0
	for _, raw := range list {
		var item struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &item); err != nil || item.ID == "" {
			continue
		}
		if _, err := c.Create(ctx, item.ID, raw); err != nil {
			if errors.Is(err, store.ErrExists) {
				continue
			}
			return n, err
		}
		n++
	}
	return n, nil
}
