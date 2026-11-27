package principal

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxClientField bounds each field of a client's self-description.
const maxClientField = 128

// Clean returns c as the gateway keeps it: without control and format
// characters (escape sequences, bidirectional and zero-width ones) and
// invalid UTF-8, each field cut to maxClientField characters. What a
// client says of itself is shown to administrators, in their terminals
// too (#409).
func (c Client) Clean() Client {
	return Client{Name: cleanField(c.Name), Version: cleanField(c.Version)}
}

func cleanField(s string) string {
	var b strings.Builder
	n := 0
	for i, r := range s {
		if r == utf8.RuneError {
			if _, size := utf8.DecodeRuneInString(s[i:]); size <= 1 {
				continue // an invalid byte
			}
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if n == maxClientField {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
