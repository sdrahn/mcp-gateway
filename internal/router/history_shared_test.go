package router

import (
	"context"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/kube/kubetest"
	"github.com/sdrahn/mcp-gateway/internal/store"
)

func sharedHistory(t *testing.T, api *kubetest.Secrets) *SharedHistory {
	t.Helper()
	c, err := store.NewKubernetes(api.Client(), "gw", "clients")
	if err != nil {
		t.Fatal(err)
	}
	tb := &store.Shared{C: c, Replica: "gw-a"}
	items, err := tb.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tb.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return &SharedHistory{Table: tb, Items: items}
}

// With a shared store the history is a record per client, read by the
// next start as the file is.
func TestHistoryShared(t *testing.T) {
	api := kubetest.NewSecrets(t)
	r, _ := testRouter(t, time.Hour)
	r.SharedHistory = sharedHistory(t, api)
	p := alice()
	c := connect(t, r, p, "fs", nil)
	c.roundTrip(1, "tools/call", map[string]any{"name": "read_file"})
	c.close()
	waitHistory(t, r, "alice", true)
	o := alice()
	o.Sub = "olga"
	connect(t, r, o, "fs", nil)
	waitHistory(t, r, "olga", false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.SharedHistory.Table.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if n := api.Len("gw"); n != 2 {
		t.Fatalf("%d records", n)
	}
	next, _ := testRouter(t, time.Hour)
	next.SharedHistory = sharedHistory(t, api)
	all := next.History(time.Time{}, time.Time{})
	if len(all) != 2 {
		t.Fatalf("restored %+v", all)
	}
	for _, rec := range all {
		if rec.Sub == "olga" && rec.End != EndRestart {
			t.Fatalf("open at the restart %+v", rec)
		}
		if rec.Sub == "alice" && (rec.End != EndDisconnected || rec.Calls != 1) {
			t.Fatalf("restored %+v", rec)
		}
	}
	if next.maxHistory() != maxSharedHistory {
		t.Errorf("bound %d", next.maxHistory())
	}
}
