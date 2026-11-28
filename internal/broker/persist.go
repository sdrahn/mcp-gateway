package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/store"
)

// stateKept is where a map of the broker's state is kept across
// restarts: a file in state_dir (a JSON list), a table of the shared
// store (a record each; docs/architecture.md, section 5.12.5), or
// nowhere.
type stateKept struct {
	file  string
	table *store.Shared
	// what names the state in messages ("pending approvals").
	what string
}

// openTable loads this replica's records of c into a table written by
// its own goroutine until ctx ends; the other replicas' are followed.
func openTable(ctx context.Context, c store.Collection, replica string, log *slog.Logger, what string) (stateKept, map[string][]byte, error) {
	t := &store.Shared{C: c, Replica: replica, Log: log, MinBackoff: sharedBackoff, MaxBackoff: 30 * sharedBackoff}
	items, err := t.Load(ctx)
	if err != nil {
		return stateKept{}, nil, fmt.Errorf("broker: %s: %w", what, err)
	}
	go t.Run(ctx)
	return stateKept{table: t, what: what}, items, nil
}

// loadList reads the state's items. A table's items come from
// openTable, which listed them.
func loadList[T any](p stateKept, items map[string][]byte, log *slog.Logger) ([]*T, error) {
	if p.table != nil {
		var out []*T
		for name, data := range items {
			v := new(T)
			if err := json.Unmarshal(data, v); err != nil {
				log.Warn("broker: record not read", "what", p.what, "name", name, "err", err)
				continue
			}
			out = append(out, v)
		}
		return out, nil
	}
	if p.file == "" {
		return nil, nil
	}
	data, err := os.ReadFile(p.file)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*T
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("broker: reading %s: %w", p.file, err)
	}
	return out, nil
}

// others returns the other replicas' items of the state, decoded, by
// id, with the replica that holds each (none without a shared store).
func others[T any](p stateKept, log *slog.Logger) map[string]*T {
	if p.table == nil {
		return nil
	}
	recs, _ := p.table.Others()
	out := make(map[string]*T, len(recs))
	for id, o := range recs {
		v := new(T)
		if err := json.Unmarshal(o.Data, v); err != nil {
			log.Debug("broker: another replica's record not read", "what", p.what, "id", id, "err", err)
			continue
		}
		out[id] = v
	}
	return out
}

// adopt takes over the records of replicas that are gone, decoded.
func adopt[T any](ctx context.Context, p stateKept, live func(string) bool, log *slog.Logger) []*T {
	if p.table == nil {
		return nil
	}
	recs, err := p.table.Adopt(ctx, live)
	if err != nil {
		log.Warn("broker: adopting the records of replicas that are gone failed", "what", p.what, "err", err)
	}
	var out []*T
	for id, data := range recs {
		v := new(T)
		if err := json.Unmarshal(data, v); err != nil {
			log.Warn("broker: adopted record not read", "what", p.what, "id", id, "err", err)
			continue
		}
		out = append(out, v)
	}
	return out
}

// saveMap keeps m: the file written whole (sorted by created), or the
// table's records made m (written by the table's goroutine). Caller
// holds b.mu.
func saveMap[T any](p stateKept, m map[string]*T, created func(*T) time.Time, log *slog.Logger) {
	if p.table != nil {
		items := make(map[string][]byte, len(m))
		for id, v := range m {
			data, err := json.Marshal(v)
			if err != nil {
				log.Warn("persisting failed", "what", p.what, "id", id, "err", err)
				continue
			}
			items[id] = data
		}
		p.table.Save(items)
		return
	}
	if p.file == "" {
		return
	}
	list := make([]*T, 0, len(m))
	for _, v := range m {
		list = append(list, v)
	}
	slices.SortFunc(list, func(x, y *T) int { return created(x).Compare(created(y)) })
	data, err := json.MarshalIndent(list, "", "  ")
	if err == nil {
		err = writeFileAtomic(p.file, append(data, '\n'))
	}
	if err != nil {
		log.Warn("persisting "+p.what+" failed", "err", err)
	}
}
