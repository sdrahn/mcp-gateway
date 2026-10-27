package polkit

import (
	"os"
	"testing"
)

func TestParseStartTime(t *testing.T) {
	// A command name with spaces and parentheses: fields follow the last ")".
	stat := "4242 (a (b) c) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1234 56 18446744073709551615"
	if st, err := parseStartTime(stat); err != nil || st != 987654 {
		t.Errorf("%d %v", st, err)
	}
	for _, bad := range []string{"", "4242 (x", "4242 (x) S 1"} {
		if _, err := parseStartTime(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
	if _, err := ProcStartTime(uint32(os.Getpid())); err != nil {
		t.Errorf("own process: %v", err)
	}
}
