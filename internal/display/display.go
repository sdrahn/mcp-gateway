// Package display shows what agents and servers send to the people who
// decide on it, so that it reads as what it is (#410): characters that
// do not show, or turn text around, are written as escapes.
package display

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf16"
)

// Hidden reports whether r is a character people do not see as itself:
// a control character but tab and newline, or a format character (the
// bidirectional controls and isolates, zero-width characters, the byte
// order mark, soft hyphen).
func Hidden(r rune) bool {
	return (unicode.IsControl(r) && r != '\t' && r != '\n') || unicode.Is(unicode.Cf, r)
}

// Escape writes each hidden character of s as \uXXXX (\U00XXXXXX
// beyond the Basic Multilingual Plane).
func Escape(s string) string { return escape(s, false) }

// JSON is v as indented JSON (json.MarshalIndent) with each hidden
// character escaped: still JSON with the same strings, as hidden
// characters only occur within its strings, where the escapes are
// JSON's. (encoding/json escapes the C0 controls but leaves the C1 ones
// and the format characters as they are.)
func JSON(v any, prefix, indent string) (string, error) {
	b, err := json.MarshalIndent(v, prefix, indent)
	if err != nil {
		return "", err
	}
	return escape(string(b), true), nil
}

// escape writes hidden characters as escapes; for JSON, one beyond the
// Basic Multilingual Plane as its UTF-16 surrogate pair.
func escape(s string, forJSON bool) string {
	if strings.IndexFunc(s, Hidden) < 0 {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case !Hidden(r):
			b.WriteRune(r)
		case r <= 0xFFFF:
			fmt.Fprintf(&b, `\u%04X`, r)
		case forJSON:
			r1, r2 := utf16.EncodeRune(r)
			fmt.Fprintf(&b, `\u%04X\u%04X`, r1, r2)
		default:
			fmt.Fprintf(&b, `\U%08X`, r)
		}
	}
	return b.String()
}
