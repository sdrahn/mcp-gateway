package pep

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// failOn fails every listing with a resource it names in it, as OPA does
// for a rule that conflicts on one tool; err is what it fails with.
type failOn struct {
	names map[string]bool
	err   error
	calls *int
}

func (f failOn) Visible(_ context.Context, _ principal.Principal, rs []Resource) ([]Resource, error) {
	*f.calls++
	for _, r := range rs {
		if f.names[r.Name] {
			return nil, f.err
		}
	}
	return rs, nil
}

var errConflict = &PolicyError{Status: "500 Internal Server Error", Body: []byte(`{"errors":[{"code":"eval_conflict_error"}]}`)}

func names(rs []Resource) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Server+"/"+r.Name)
	}
	slices.Sort(out)
	return out
}

func TestVisibleContained(t *testing.T) {
	rs := []Resource{
		{Server: "fs", Kind: "tool", Name: "read_file"},
		{Server: "fs", Kind: "tool", Name: "write_file"},
		{Server: "tukit", Kind: "tool", Name: "reboot"},
		{Server: "tukit", Kind: "tool", Name: "apply"},
	}
	ctx := context.Background()
	p := principal.Principal{Sub: "drahn"}

	calls := 0
	vs, undecided, err := VisibleContained(ctx, failOn{map[string]bool{"reboot": true}, errConflict, &calls}, p, rs)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(vs); !slices.Equal(got, []string{"fs/read_file", "fs/write_file", "tukit/apply"}) {
		t.Errorf("visible %v", got)
	}
	if len(undecided) != 1 || undecided[0].Server != "tukit" || names(undecided[0].Resources)[0] != "tukit/reboot" ||
		len(undecided[0].Resources) != 1 || !errors.Is(undecided[0].Err, errConflict) {
		t.Errorf("undecided %+v", undecided)
	}
	// One listing, one per server, one per tool of the failing server.
	if calls != 1+2+2 {
		t.Errorf("%d queries", calls)
	}

	// Decided at once: one query.
	calls = 0
	if vs, undecided, err := VisibleContained(ctx, failOn{nil, errConflict, &calls}, p, rs); err != nil || len(vs) != 4 || undecided != nil || calls != 1 {
		t.Errorf("ok: %d %v %v, %d queries", len(vs), undecided, err, calls)
	}

	// Failing for every server: not decided tool by tool.
	calls = 0
	all := map[string]bool{"read_file": true, "write_file": true, "reboot": true, "apply": true}
	vs, undecided, err = VisibleContained(ctx, failOn{all, errConflict, &calls}, p, rs)
	if err != nil || vs != nil || len(undecided) != 2 || len(undecided[0].Resources) != 2 || calls != 1+2 {
		t.Errorf("all: %v %+v %v, %d queries", vs, undecided, err, calls)
	}

	// One server, failing on one tool: tool by tool.
	calls = 0
	vs, undecided, err = VisibleContained(ctx, failOn{map[string]bool{"write_file": true}, errConflict, &calls}, p, rs[:2])
	if err != nil || !slices.Equal(names(vs), []string{"fs/read_file"}) || len(undecided) != 1 || calls != 1+1+2 {
		t.Errorf("one server: %v %+v %v, %d queries", vs, undecided, err, calls)
	}

	// OPA out of reach: nothing decided, no more queries.
	calls = 0
	down := errors.New("opa: connection refused")
	if vs, undecided, err := VisibleContained(ctx, failOn{map[string]bool{"reboot": true}, down, &calls}, p, rs); !errors.Is(err, down) || vs != nil || undecided != nil || calls != 1 {
		t.Errorf("down: %v %v %v, %d queries", vs, undecided, err, calls)
	}
}
