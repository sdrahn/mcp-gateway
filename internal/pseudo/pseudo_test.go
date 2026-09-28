package pseudo

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func mustCompile(t *testing.T, s *Spec) *Compiled {
	t.Helper()
	c, err := Compile(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func apply(t *testing.T, v *Vault, c *Compiled, doc string) (string, Stats) {
	t.Helper()
	out, st, err := v.Apply(c, json.RawMessage(doc))
	if err != nil {
		t.Fatal(err)
	}
	return string(out), st
}

func textOf(t *testing.T, doc string) string {
	t.Helper()
	var r struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal([]byte(doc), &r); err != nil || len(r.Content) == 0 {
		t.Fatalf("not a tool result: %s", doc)
	}
	return r.Content[0].Text
}

func toolResult(text string) string {
	b, _ := json.Marshal(map[string]any{"content": []map[string]any{{"type": "text", "text": text}}})
	return string(b)
}

func TestDetectors(t *testing.T) {
	all := mustCompile(t, &Spec{Detect: []string{"email", "iban", "credit_card", "phone", "ipv4", "ipv6"}})
	cases := []struct{ in, want string }{
		{"mail alice@example.com now", "mail [EMAIL_1] now"},
		{"IBAN DE89370400440532013000.", "IBAN [IBAN_1]."},
		{"IBAN DE89 3704 0044 0532 0130 00 please", "IBAN [IBAN_1] please"},
		{"bad DE89370400440532013001", "bad DE89370400440532013001"}, // checksum
		{"card 4111 1111 1111 1111 ok", "card [CARD_1] ok"},
		{"card 4111111111111112", "card 4111111111111112"}, // Luhn
		{"call +49 30 1234567 today", "call [PHONE_1] today"},
		{"host 10.1.2.3 up", "host [IP_1] up"},
		{"host 2001:db8::8a2e:370:7334 up", "host [IP_1] up"},
		{"std::string and 12:30:45", "std::string and 12:30:45"},
		{"version 1.2.3 and 1+1 2", "version 1.2.3 and 1+1 2"},
	}
	for _, tc := range cases {
		got, _ := apply(t, NewVault(0), all, toolResult(tc.in))
		if got := textOf(t, got); got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestConsistentTokens(t *testing.T) {
	c := mustCompile(t, &Spec{Detect: []string{"email"}})
	v := NewVault(0)
	out, st := apply(t, v, c, toolResult("a@x.org b@x.org a@x.org"))
	if got := textOf(t, out); got != "[EMAIL_1] [EMAIL_2] [EMAIL_1]" {
		t.Errorf("got %q", got)
	}
	if st["EMAIL"] != 3 {
		t.Errorf("stats %v", st)
	}
	// Later results reuse the tokens.
	out, _ = apply(t, v, c, toolResult("from b@x.org"))
	if got := textOf(t, out); got != "from [EMAIL_2]" {
		t.Errorf("second result: %q", got)
	}
	// Another session has its own tokens.
	out, _ = apply(t, NewVault(0), c, toolResult("from b@x.org"))
	if got := textOf(t, out); got != "from [EMAIL_1]" {
		t.Errorf("other vault: %q", got)
	}
}

func TestPatterns(t *testing.T) {
	c := mustCompile(t, &Spec{Patterns: map[string]string{"customer": `CUST-[0-9]{6}`}})
	out, _ := apply(t, NewVault(0), c, toolResult("ticket for CUST-004711"))
	if got := textOf(t, out); got != "ticket for [CUSTOMER_1]" {
		t.Errorf("got %q", got)
	}
}

func TestFields(t *testing.T) {
	c := mustCompile(t, &Spec{Fields: map[string]string{"name": "person", "id": "customer", "address": "address"}, Detect: []string{"email"}})
	v := NewVault(0)
	doc := `{"structuredContent":{"customers":[{"id":4711,"name":"Alice Doe","note":"mail a@x.org","address":{"street":"Main St 1","city":"Nuremberg"}}]},` +
		`"content":[{"type":"text","text":"{\"id\":4711,\"name\":\"Alice Doe\"}"}]}`
	out, st := apply(t, v, c, doc)
	var r struct {
		Structured struct {
			Customers []map[string]any `json:"customers"`
		} `json:"structuredContent"`
		Content []struct {
			Type, Text string
		} `json:"content"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	cust := r.Structured.Customers[0]
	if cust["id"] != "[CUSTOMER_1]" || cust["name"] != "[PERSON_1]" || cust["note"] != "mail [EMAIL_1]" {
		t.Errorf("fields: %v", cust)
	}
	addr := cust["address"].(map[string]any)
	if addr["city"] != "[ADDRESS_1]" || addr["street"] != "[ADDRESS_2]" {
		t.Errorf("nested field: %v", addr)
	}
	// JSON returned as text is walked too, with the same tokens.
	if r.Content[0].Type != "text" || r.Content[0].Text != `{"id":"[CUSTOMER_1]","name":"[PERSON_1]"}` {
		t.Errorf("embedded JSON: %+v", r.Content[0])
	}
	if st["PERSON"] != 2 || st["CUSTOMER"] != 2 || st["EMAIL"] != 1 {
		t.Errorf("stats %v", st)
	}
}

func TestBinaryLeftAlone(t *testing.T) {
	c := mustCompile(t, &Spec{Detect: []string{"credit_card"}, Fields: map[string]string{"data": "x"}})
	doc := `{"content":[{"type":"image","mimeType":"image/png","data":"4111111111111111"}],` +
		`"contents":[{"uri":"file:///a","mimeType":"application/octet-stream","blob":"4111111111111111"}]}`
	out, _ := apply(t, NewVault(0), c, doc)
	if strings.Count(out, "4111111111111111") != 2 {
		t.Errorf("binary content changed: %s", out)
	}
}

func TestLimit(t *testing.T) {
	c := mustCompile(t, &Spec{Detect: []string{"email"}})
	v := NewVault(2)
	out, st := apply(t, v, c, toolResult("a@x.org b@x.org c@x.org a@x.org"))
	if got := textOf(t, out); got != "[EMAIL_1] [EMAIL_2] [EMAIL_REDACTED] [EMAIL_1]" {
		t.Errorf("got %q", got)
	}
	if st["REDACTED"] != 1 || v.Len() != 2 {
		t.Errorf("stats %v len %d", st, v.Len())
	}
}

func TestReidentify(t *testing.T) {
	c := mustCompile(t, &Spec{Detect: []string{"email"}, Fields: map[string]string{"id": "customer"}})
	v := NewVault(0)
	apply(t, v, c, `{"id":4711,"mail":"a@x.org"}`)

	args := map[string]any{
		"id":    "[CUSTOMER_1]",
		"body":  "Dear [EMAIL_1], see [EMAIL_9] and [PHONE_1]",
		"cc":    []any{"[EMAIL_1]"},
		"other": "[EMAIL_1]",
	}
	got, changed, n := v.Reidentify(args, []string{"id", "body", "cc", "missing"})
	want := map[string]any{
		"id":    json.Number("4711"),
		"body":  "Dear a@x.org, see [EMAIL_9] and [PHONE_1]",
		"cc":    []any{"a@x.org"},
		"other": "[EMAIL_1]", // not named: stays a token
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %#v", got)
	}
	if n != 3 || !reflect.DeepEqual(changed, []string{"body", "cc", "id"}) {
		t.Errorf("n=%d changed=%v", n, changed)
	}
	if args["id"] != "[CUSTOMER_1]" || args["cc"].([]any)[0] != "[EMAIL_1]" {
		t.Error("Reidentify modified its input")
	}
	if _, _, n := NewVault(0).Reidentify(args, []string{"id"}); n != 0 {
		t.Error("another session's vault re-identified a token")
	}
}

func TestCompileErrors(t *testing.T) {
	for _, s := range []*Spec{
		{Detect: []string{"passport"}},
		{Patterns: map[string]string{"Bad-Name": "x"}},
		{Patterns: map[string]string{"x": "("}},
		{Patterns: map[string]string{"x": "a*"}},
		{Fields: map[string]string{"name": "Person!"}},
		{Fields: map[string]string{"": "person"}},
	} {
		if _, err := Compile(s); err == nil {
			t.Errorf("%+v compiled", s)
		}
	}
	if c, err := Compile(&Spec{}); c != nil || err != nil {
		t.Errorf("empty spec: %v %v", c, err)
	}
}

func TestStatsString(t *testing.T) {
	if s := (Stats{"PERSON": 1, "EMAIL": 2}).String(); s != "EMAIL:2 PERSON:1" {
		t.Errorf("got %q", s)
	}
}
