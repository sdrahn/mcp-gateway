package pep

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/pseudo"
)

func TestCompileRejectsMalformed(t *testing.T) {
	for name, o := range map[string]Obligations{
		"bad regex":      {RedactOutput: []string{"("}},
		"negative size":  {MaxOutputBytes: -1},
		"bad rate":       {RateLimit: StringList{"lots"}},
		"bad rate unit":  {RateLimit: StringList{"5/d"}},
		"zero rate":      {RateLimit: StringList{"0/m"}},
		"bad constraint": {ArgConstraints: map[string]StringList{"path": {"["}}},
		"bad audit":      {Audit: "loud"},
		"bad detector":   {Pseudonymize: &pseudo.Spec{Detect: []string{"passport"}}},
		"bad pattern":    {Pseudonymize: &pseudo.Spec{Patterns: map[string]string{"x": "("}}},
		"empty reident.": {Reidentify: StringList{""}},
	} {
		if _, err := o.Compile(); err == nil {
			t.Errorf("%s: expected error", name)
		}
		d := Decision{Effect: Allow, Obligations: &o}
		if err := d.Validate(); err == nil {
			t.Errorf("%s: decision should be invalid", name)
		}
	}
}

func TestRateLimitStringOrList(t *testing.T) {
	var o Obligations
	if err := json.Unmarshal([]byte(`{"rate_limit":"3/s"}`), &o); err != nil || len(o.RateLimit) != 1 {
		t.Fatalf("string: %+v %v", o, err)
	}
	if err := json.Unmarshal([]byte(`{"rate_limit":["3/s","10/m"]}`), &o); err != nil || len(o.RateLimit) != 2 {
		t.Fatalf("list: %+v %v", o, err)
	}
	if err := json.Unmarshal([]byte(`{"rate_limit":3}`), &o); err == nil {
		t.Fatal("number accepted")
	}
}

func TestRedactAndSize(t *testing.T) {
	o := Obligations{RedactOutput: []string{`(?i)password=\S+`, `AKIA[0-9A-Z]{16}`}, MaxOutputBytes: 200}
	c, err := o.Compile()
	if err != nil {
		t.Fatal(err)
	}
	in := json.RawMessage(`{"content":[{"type":"text","text":"user=bob password=hunter2 key AKIAABCDEFGHIJKLMNOP"}],"isError":false}`)
	out, _, err := c.ApplyOutput(in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "hunter2") || strings.Contains(string(out), "AKIA") || strings.Count(string(out), Redacted) != 2 {
		t.Fatalf("not redacted: %s", out)
	}
	if !strings.Contains(string(out), `"isError":false`) {
		t.Fatalf("structure changed: %s", out)
	}
	big := json.RawMessage(`{"text":"` + strings.Repeat("x", 300) + `"}`)
	if _, _, err := c.ApplyOutput(big, nil); err == nil {
		t.Fatal("size limit not enforced")
	}
}

func TestCheckArgs(t *testing.T) {
	o := Obligations{ArgConstraints: map[string]StringList{"path": {`^/srv/`, `\.txt$`}}}
	c, _ := o.Compile()
	if err := c.CheckArgs(map[string]any{"path": "/srv/a.txt"}); err != nil {
		t.Fatal(err)
	}
	for _, args := range []map[string]any{{"path": "/etc/passwd"}, {"path": "/srv/a.sh"}, {}, {"path": 3}} {
		if err := c.CheckArgs(args); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter()
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	rates := []Rate{{N: 2, Per: time.Second}, {N: 3, Per: time.Minute}}
	for i := range 2 {
		if !l.Allow("k", rates) {
			t.Fatalf("call %d refused", i+1)
		}
	}
	if l.Allow("k", rates) {
		t.Fatal("third within a second allowed")
	}
	if !l.Allow("other", rates) {
		t.Fatal("keys not independent")
	}
	now = now.Add(2 * time.Second)
	if !l.Allow("k", rates) {
		t.Fatal("per-second window did not slide")
	}
	now = now.Add(2 * time.Second)
	if l.Allow("k", rates) {
		t.Fatal("per-minute limit not enforced")
	}
	now = now.Add(time.Minute)
	if !l.Allow("k", rates) {
		t.Fatal("per-minute window did not slide")
	}
}

func TestApplyOutputPseudonymizes(t *testing.T) {
	var o Obligations
	if err := json.Unmarshal([]byte(`{"pseudonymize":{"detect":["email"]},"reidentify":"to","redact_output":["secret"]}`), &o); err != nil {
		t.Fatal(err)
	}
	c, err := o.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Reidentify) != 1 || c.Reidentify[0] != "to" {
		t.Errorf("reidentify: %v", c.Reidentify)
	}
	in := json.RawMessage(`{"content":[{"type":"text","text":"secret from a@x.org"}]}`)
	out, st, err := c.ApplyOutput(in, pseudo.NewVault(0))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), Redacted+" from [EMAIL_1]") || st["EMAIL"] != 1 {
		t.Errorf("got %s %v", out, st)
	}
	if _, _, err := c.ApplyOutput(in, nil); err == nil {
		t.Error("pseudonymization without a vault must fail")
	}
	// The size limit applies to the pseudonymized result.
	c.MaxOutputBytes = int64(len(out))
	if _, _, err := c.ApplyOutput(in, pseudo.NewVault(0)); err != nil {
		t.Errorf("limit on the pseudonymized size: %v", err)
	}
}
