package proposal

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const good = `{"summary": "Install the 2 security patches for openssl; nginx restarts.",
 "impact": "nginx is unavailable for about 5 s.",
 "steps": ["zypper patch --cve CVE-2026-1234", "systemctl restart nginx"],
 "context": {"activity": "e-1", "started_by": "schedule morning-check"},
 "warnings": ["suspected prompt injection"]}`

func TestParse(t *testing.T) {
	p, err := Parse(json.RawMessage(good))
	if err != nil {
		t.Fatal(err)
	}
	if !p.ClientSupplied || p.Summary == "" || len(p.Steps) != 2 || p.Context["activity"] != "e-1" || len(p.Warnings) != 1 {
		t.Fatalf("%+v", p)
	}
	// The client cannot say it is not its claim.
	if p, err := Parse(json.RawMessage(`{"summary": "x", "client_supplied": false}`)); err != nil || !p.ClientSupplied {
		t.Fatalf("client_supplied from the client: %+v %v", p, err)
	}
	if p, err := Parse(json.RawMessage(`{"summary": "x", "impact": "two\nlines"}`)); err != nil || p.Impact != "two\nlines" {
		t.Fatalf("impact with lines: %+v %v", p, err)
	}
}

func TestParseRefuses(t *testing.T) {
	long := strings.Repeat("x", MaxLine+1)
	many := func(n int) string {
		return `["` + strings.TrimSuffix(strings.Repeat(`a","`, n), `","`) + `"]`
	}
	ctx := map[string]string{}
	for i := range MaxContext + 1 {
		ctx[string(rune('a'+i))] = "v"
	}
	ctxJSON, _ := json.Marshal(ctx)
	for name, raw := range map[string]string{
		"not JSON":          `{`,
		"not an object":     `"x"`,
		"unknown field":     `{"summary": "x", "approve": true}`,
		"no summary":        `{"impact": "x"}`,
		"blank summary":     `{"summary": "  "}`,
		"two-line summary":  `{"summary": "a\nb"}`,
		"long summary":      `{"summary": "` + strings.Repeat("s", MaxSummary+1) + `"}`,
		"escape":            `{"summary": "a\u001b[2Jb"}`,
		"bidi override":     "{\"summary\": \"a\u202eb\"}",
		"long impact":       `{"summary": "x", "impact": "` + strings.Repeat("i", MaxImpact+1) + `"}`,
		"too many steps":    `{"summary": "x", "steps": ` + many(MaxSteps+1) + `}`,
		"too many warnings": `{"summary": "x", "warnings": ` + many(MaxWarnings+1) + `}`,
		"long step":         `{"summary": "x", "steps": ["` + long + `"]}`,
		"empty warning":     `{"summary": "x", "warnings": [""]}`,
		"too much context":  `{"summary": "x", "context": ` + string(ctxJSON) + `}`,
		"context not text":  `{"summary": "x", "context": {"a": 1}}`,
		"two-line context":  `{"summary": "x", "context": {"a": "b\nc"}}`,
		"too large in all":  `{"summary": "x", "impact": "` + strings.Repeat("i", MaxTotal) + `"}`,
		"trailing value":    `{"summary": "x"} {}`,
	} {
		if _, err := Parse(json.RawMessage(raw)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDigest(t *testing.T) {
	a, _ := Parse(json.RawMessage(`{"summary": "x", "context": {"b": "2", "a": "1"}}`))
	b, _ := Parse(json.RawMessage(`{"context": {"a": "1", "b": "2"}, "summary": "x"}`))
	c, _ := Parse(json.RawMessage(`{"summary": "y"}`))
	if !strings.HasPrefix(a.Digest(), "sha256:") || a.Digest() != b.Digest() || a.Digest() == c.Digest() {
		t.Fatalf("%s %s %s", a.Digest(), b.Digest(), c.Digest())
	}
	var none *Proposal
	if none.Digest() != "" {
		t.Fatal("nil digest")
	}
}

func TestTake(t *testing.T) {
	meta := json.RawMessage(`{"progressToken": "p1", "` + Key + `": ` + good + `}`)
	rest, p, err := Take(meta)
	if err != nil || p == nil || string(rest) != `{"progressToken":"p1"}` {
		t.Fatalf("%s %+v %v", rest, p, err)
	}
	// An invalid one is removed all the same.
	rest, p, err = Take(json.RawMessage(`{"` + Key + `": {"summary": ""}}`))
	if !errors.Is(err, ErrInvalid) || p != nil || string(rest) != `{}` {
		t.Fatalf("invalid: %s %+v %v", rest, p, err)
	}
	// Without one, unchanged.
	if rest, p, err := Take(json.RawMessage(`{"progressToken": 1}`)); err != nil || p != nil || string(rest) != `{"progressToken": 1}` {
		t.Fatalf("none: %s %+v %v", rest, p, err)
	}
}
