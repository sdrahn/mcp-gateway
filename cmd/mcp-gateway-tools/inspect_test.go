package main

import (
	"bytes"
	"testing"
)

func TestInspectUsage(t *testing.T) {
	for _, c := range []struct {
		args []string
		code int
	}{
		{nil, 2}, // neither -server nor a command
		{[]string{"-server", "x", "--", "/bin/true"}, 2}, // both
		{[]string{"--", "/bin/true"}, 2},                 // a command without -name
		{[]string{"-h"}, 0},
	} {
		var out, errOut bytes.Buffer
		if got := runInspect(c.args, &out, &errOut); got != c.code {
			t.Errorf("%v: exit %d, want %d\n%s", c.args, got, c.code, errOut.String())
		}
	}
}
