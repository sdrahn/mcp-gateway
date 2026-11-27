package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

// What reaches a terminal holds no control or format character but tab
// and newline, however the text is split into writes (#409).
func TestTermSafe(t *testing.T) {
	in := "ok évé\tcol\nCSI \x1b[2J OSC \x1b]52;c;aGk=\x07 C1 \u009b31m RLO \u202e ZW \u200b bad \xff end é"
	want := `ok évé` + "\t" + `col` + "\n" + `CSI \u001B[2J OSC \u001B]52;c;aGk=\u0007 C1 \u009B31m RLO \u202E ZW \u200B bad \xFF end é`
	for _, chunk := range []int{len(in), 1, 2, 3} {
		var out bytes.Buffer
		ts := &termSafe{w: &out}
		b := []byte(in)
		for len(b) > 0 {
			n := min(chunk, len(b))
			if k, err := ts.Write(b[:n]); err != nil || k != n {
				t.Fatalf("write: %d %v", k, err)
			}
			b = b[n:]
		}
		if out.String() != want {
			t.Errorf("chunks of %d:\n got %q\nwant %q", chunk, out.String(), want)
		}
	}
	// JSON stays JSON, with the same strings.
	var out bytes.Buffer
	enc, _ := json.Marshal(map[string]string{"name": "a\u202eb\u009bc"})
	_, _ = (&termSafe{w: &out}).Write(enc)
	var back map[string]string
	if err := json.Unmarshal(out.Bytes(), &back); err != nil || back["name"] != "a\u202eb\u009bc" {
		t.Errorf("JSON %s: %v %q", out.String(), err, back)
	}
}
