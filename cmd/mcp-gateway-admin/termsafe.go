package main

import (
	"fmt"
	"io"
	"os"
	"unicode"
	"unicode/utf8"
)

// terminal returns f as the commands write to it: through termSafe when
// it is a terminal; as it is otherwise, so that what goes to a file or a
// pipe (data for a file, JSON for a program) is not changed.
func terminal(f *os.File) io.Writer {
	if fi, err := f.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		return &termSafe{w: f}
	}
	return f
}

// termSafe writes to a terminal what the commands print, with every
// control and format character but tab and newline written as an escape
// (\u001B, \u202E) and an invalid byte as \xFF: much of what they print
// comes from clients, servers and identity providers (names, tool
// names, notices), and none of it may move the cursor, change colors or
// the clipboard, or turn text around in the administrator's terminal
// (#409). JSON output stays JSON: such characters only occur in its
// strings, where the \u escapes are JSON's (json.Marshal writes no
// invalid UTF-8).
type termSafe struct {
	w io.Writer
	// rest is the start of a character a write ended in.
	rest []byte
}

func (t *termSafe) Write(p []byte) (int, error) {
	buf := append(t.rest, p...)
	t.rest = nil
	out := make([]byte, 0, len(buf))
	for i := 0; i < len(buf); {
		r, size := utf8.DecodeRune(buf[i:])
		if r == utf8.RuneError && size <= 1 {
			if !utf8.FullRune(buf[i:]) {
				t.rest = append([]byte(nil), buf[i:]...)
				break
			}
			out = fmt.Appendf(out, `\x%02X`, buf[i])
			i++
			continue
		}
		if r != '\t' && r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
			out = fmt.Appendf(out, `\u%04X`, r)
		} else {
			out = append(out, buf[i:i+size]...)
		}
		i += size
	}
	if _, err := t.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}
