package jsonrpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"
)

// CheckKeys reports an object (at any depth) in raw with two keys that
// are equal, or equal but for case. The gateway decides on parameters as
// it decodes them, with exact keys, and forwards them to an MCP server
// that may decode them differently: Go's encoding/json matches struct
// fields case-insensitively and keeps the last of several matches,
// other parsers keep the first. With {"path": "/home/a", "Path": "/etc"}
// policy would see one path and the server use the other. Such keys have
// no use in MCP, so requests with them are refused.
func CheckKeys(raw json.RawMessage) error {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := checkValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

func checkValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]string{} // folded key to key
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return err
			}
			k, _ := kt.(string)
			f := foldKey(k)
			if prev, dup := seen[f]; dup {
				if prev == k {
					return fmt.Errorf("key %q appears twice in an object", k)
				}
				return fmt.Errorf("keys %q and %q differ only in case", prev, k)
			}
			seen[f] = k
			if err := checkValue(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token() // }
		return err
	case json.Delim('['):
		for dec.More() {
			if err := checkValue(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token() // ]
		return err
	}
	return nil
}

// foldKey maps a key to a representative of its case-folding class, so
// that two keys strings.EqualFold (and encoding/json) consider equal get
// the same representative: each rune becomes the smallest rune of its
// simple folding orbit (k, K and the Kelvin sign all become K).
func foldKey(s string) string {
	b := make([]byte, 0, len(s))
	for _, r := range s {
		min := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < min {
				min = f
			}
		}
		b = utf8.AppendRune(b, min)
	}
	return string(b)
}
