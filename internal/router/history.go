package router

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/store"
)

// The clients' history: each session from its initialize to its end, and
// each agent of 2026-07-28 from its first request until it is no longer
// seen (agentSeenFor), with the tool calls it made. Kept for
// HistoryRetention, across restarts (HistoryFile), for the control API's
// GET /v1/sessions/history (Cockpit's Clients tab).

const (
	// defaultHistoryRetention is how long an ended client is kept.
	defaultHistoryRetention = 30 * 24 * time.Hour
	// maxHistory bounds the records kept; the oldest ended go first.
	maxHistory = 10000
	// maxSharedHistory bounds them in a shared store, a Secret each: a
	// list of the collection stays a few megabytes.
	maxSharedHistory = 2000
)

// SharedHistory is the history in a shared store: a table (a record per
// client, this replica's; the others' followed), and the records it held
// at the start.
type SharedHistory struct {
	Table *store.Shared
	Items map[string][]byte
}

// AdoptHistory takes over the history of replicas that are gone (live
// reports which are not): their clients ended when their replica did.
func (r *Router) AdoptHistory(ctx context.Context, live func(replica string) bool) {
	if r.SharedHistory == nil {
		return
	}
	recs, err := r.SharedHistory.Table.Adopt(ctx, live)
	if err != nil {
		r.Log.Warn("client history: adopting the records of replicas that are gone failed", "err", err)
	}
	if len(recs) == 0 {
		return
	}
	now := time.Now()
	r.hist.mu.Lock()
	defer r.hist.mu.Unlock()
	r.loadHistory()
	for id, data := range recs {
		rec := new(ClientRecord)
		if json.Unmarshal(data, rec) != nil || r.hist.records[id] != nil {
			continue
		}
		if rec.Ended == nil {
			t := rec.LastActive
			if t.Before(rec.Started) {
				t = rec.Started
			}
			rec.Ended, rec.End = &t, EndRestart
		}
		r.hist.records[id] = rec
	}
	r.persistHistory(now)
}

// otherHistory returns the other replicas' clients (several replicas).
func (r *Router) otherHistory() []*ClientRecord {
	if r.SharedHistory == nil {
		return nil
	}
	recs, _ := r.SharedHistory.Table.Others()
	out := make([]*ClientRecord, 0, len(recs))
	for _, o := range recs {
		rec := new(ClientRecord)
		if json.Unmarshal(o.Data, rec) == nil {
			out = append(out, rec)
		}
	}
	return out
}

func (r *Router) maxHistory() int {
	if r.SharedHistory != nil {
		return maxSharedHistory
	}
	return maxHistory
}

// How a client ended (ClientRecord.End).
const (
	EndDisconnected = "disconnected"    // the client went (or the gateway stopped it)
	EndEnded        = "ended"           // ended by an administrator (EndedBy)
	EndNotSeen      = "not seen"        // an agent of 2026-07-28 that made no request for an hour
	EndRestart      = "gateway stopped" // still open when the gateway stopped
)

// ClientRecord is a client in the history: as Sessions lists it, with
// when and how it ended and the tool calls the gateway forwarded for it.
type ClientRecord struct {
	SessionInfo
	// Ended is when it ended (nil: connected); End says how, EndedBy who
	// ended it (End "ended").
	Ended   *time.Time `json:"ended,omitempty"`
	End     string     `json:"end,omitempty"`
	EndedBy string     `json:"ended_by,omitempty"`
	// Calls counts the tool calls forwarded for it.
	Calls int `json:"calls"`
}

// history holds the records, by record id.
type history struct {
	mu      sync.Mutex
	loaded  bool
	records map[string]*ClientRecord
}

func (r *Router) historyRetention() time.Duration {
	if r.HistoryRetention > 0 {
		return r.HistoryRetention
	}
	return defaultHistoryRetention
}

// loadHistory reads the history file once; clients still open in it
// ended when the gateway stopped. Caller holds r.hist.mu.
func (r *Router) loadHistory() {
	h := &r.hist
	if h.loaded {
		return
	}
	h.loaded = true
	h.records = map[string]*ClientRecord{}
	var list []*ClientRecord
	if r.SharedHistory != nil {
		for name, data := range r.SharedHistory.Items {
			rec := new(ClientRecord)
			if err := json.Unmarshal(data, rec); err != nil {
				r.Log.Warn("client history: record not read", "name", name, "err", err)
				continue
			}
			list = append(list, rec)
		}
	} else {
		if r.HistoryFile == "" {
			return
		}
		data, err := os.ReadFile(r.HistoryFile)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				r.Log.Warn("client history not read", "file", r.HistoryFile, "err", err)
			}
			return
		}
		if err := json.Unmarshal(data, &list); err != nil {
			r.Log.Warn("client history not read", "file", r.HistoryFile, "err", err)
			return
		}
	}
	for _, rec := range list {
		if rec.ID == "" {
			continue
		}
		if rec.Ended == nil {
			t := rec.LastActive
			if t.Before(rec.Started) {
				t = rec.Started
			}
			rec.Ended, rec.End = &t, EndRestart
		}
		h.records[rec.ID] = rec
	}
}

// persistHistory prunes and writes the history. Caller holds r.hist.mu.
func (r *Router) persistHistory(now time.Time) {
	h := &r.hist
	cutoff := now.Add(-r.historyRetention())
	for id, rec := range h.records {
		if rec.Ended != nil && rec.Ended.Before(cutoff) {
			delete(h.records, id)
		}
	}
	if len(h.records) > r.maxHistory() {
		var ended []*ClientRecord
		for _, rec := range h.records {
			if rec.Ended != nil {
				ended = append(ended, rec)
			}
		}
		slices.SortFunc(ended, func(a, b *ClientRecord) int { return a.Ended.Compare(*b.Ended) })
		for _, rec := range ended {
			if len(h.records) <= r.maxHistory() {
				break
			}
			delete(h.records, rec.ID)
		}
	}
	if r.SharedHistory != nil {
		// Written by the table's own writer.
		items := make(map[string][]byte, len(h.records))
		for id, rec := range h.records {
			if data, err := json.Marshal(rec); err == nil {
				items[id] = data
			}
		}
		r.SharedHistory.Table.Save(items)
		return
	}
	if r.HistoryFile == "" {
		return
	}
	list := make([]*ClientRecord, 0, len(h.records))
	for _, rec := range h.records {
		list = append(list, rec)
	}
	slices.SortFunc(list, func(a, b *ClientRecord) int { return a.Started.Compare(b.Started) })
	data, err := json.Marshal(list)
	if err == nil {
		err = writeFileAtomic(r.HistoryFile, append(data, '\n'))
	}
	if err != nil {
		r.Log.Warn("client history not written", "file", r.HistoryFile, "err", err)
	}
}

// historyOpen records a client that began (a session initialized, an
// agent's first request).
func (r *Router) historyOpen(info SessionInfo) {
	r.hist.mu.Lock()
	defer r.hist.mu.Unlock()
	r.loadHistory()
	info.Instances, info.Streams, info.Requests = nil, 0, 0
	r.hist.records[info.ID] = &ClientRecord{SessionInfo: info}
	r.persistHistory(time.Now())
}

// historyTouch notes that client id was active at t, and with call that
// the gateway forwarded a tool call for it (in memory: written when the
// client ends).
func (r *Router) historyTouch(id string, t time.Time, call bool) {
	if id == "" {
		return
	}
	r.hist.mu.Lock()
	defer r.hist.mu.Unlock()
	r.loadHistory()
	rec := r.hist.records[id]
	if rec == nil || rec.Ended != nil {
		return
	}
	if t.After(rec.LastActive) {
		rec.LastActive = t
	}
	if call {
		rec.Calls++
	}
}

// historyClose records that client id ended at t, how (end) and by whom.
func (r *Router) historyClose(id string, t time.Time, end, by string) {
	r.hist.mu.Lock()
	defer r.hist.mu.Unlock()
	r.loadHistory()
	rec := r.hist.records[id]
	if rec == nil || rec.Ended != nil {
		return
	}
	if rec.End == "" || end == EndEnded {
		rec.End, rec.EndedBy = end, by
	}
	if t.After(rec.LastActive) && end != EndNotSeen {
		rec.LastActive = t
	}
	rec.Ended = &t
	r.persistHistory(t)
}

// markEnded records that an administrator is ending client id (the end
// itself follows when its connection closes).
func (r *Router) markEnded(id, by string) {
	r.hist.mu.Lock()
	defer r.hist.mu.Unlock()
	r.loadHistory()
	if rec := r.hist.records[id]; rec != nil && rec.Ended == nil {
		rec.End, rec.EndedBy = EndEnded, by
	}
}

// History lists the clients connected at some time between since and
// until (zero: no bound), oldest first: those connected now too.
func (r *Router) History(since, until time.Time) []ClientRecord {
	r.init()
	others := r.otherHistory()
	r.hist.mu.Lock()
	r.loadHistory()
	out := []ClientRecord{}
	all := make([]*ClientRecord, 0, len(r.hist.records)+len(others))
	for _, rec := range r.hist.records {
		all = append(all, rec)
	}
	for _, rec := range others {
		if r.hist.records[rec.ID] == nil {
			all = append(all, rec)
		}
	}
	for _, rec := range all {
		if !until.IsZero() && rec.Started.After(until) {
			continue
		}
		if !since.IsZero() && rec.Ended != nil && rec.Ended.Before(since) {
			continue
		}
		c := *rec
		c.Servers = slices.Clone(rec.Servers)
		out = append(out, c)
	}
	r.hist.mu.Unlock()
	// The clients connected now: their activity as Sessions has it.
	live := map[string]SessionInfo{}
	for _, c := range r.Sessions() {
		live[c.ID] = c
	}
	r.agentMu.Lock()
	for _, c := range r.agents.clients {
		if info, ok := live[c.id]; ok {
			live[c.record] = info
		}
	}
	r.agentMu.Unlock()
	for i := range out {
		if info, ok := live[out[i].ID]; ok && out[i].Ended == nil && info.LastActive.After(out[i].LastActive) {
			out[i].LastActive = info.LastActive
		}
	}
	slices.SortFunc(out, func(a, b ClientRecord) int {
		if c := a.Started.Compare(b.Started); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// agentRecordID is a history record id for an agent of 2026-07-28 first
// seen now: its client id with a suffix, as the client id is the same
// each time the agent comes back.
func agentRecordID(clientID string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return clientID + "-" + hex.EncodeToString(b)
}

// writeFileAtomic writes data to path through a temporary file.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// historyID is the history record of the client s serves: its session,
// or the agent of 2026-07-28 it serves a request of.
func (s *Session) historyID() string {
	if s.agentRecord != "" {
		return s.agentRecord
	}
	return s.principal.SessionID
}
