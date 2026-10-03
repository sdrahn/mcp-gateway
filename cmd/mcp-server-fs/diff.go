package main

import (
	"fmt"
	"strings"
)

// unifiedDiff returns a unified diff (three lines of context) between a
// and b, labelled with name. Lines that differ in the middle are paired by
// a longest common subsequence where that is small enough to compute;
// otherwise the middle is shown as removed and added.
func unifiedDiff(name, a, b string) string {
	if a == b {
		return ""
	}
	x, y := splitLines(a), splitLines(b)
	ops := diffLines(x, y)
	const context = 3
	var out strings.Builder
	fmt.Fprintf(&out, "--- a/%s\n+++ b/%s\n", name, name)
	for i := 0; i < len(ops); {
		if ops[i].kind == ' ' {
			i++
			continue
		}
		// A hunk: from context lines before the change to context lines
		// after the last change that is at most 2*context lines away.
		start := i - context
		if start < 0 {
			start = 0
		}
		end := i
		for j := i; j < len(ops); j++ {
			if ops[j].kind != ' ' {
				end = j
			} else if j-end > 2*context {
				break
			}
		}
		stop := end + context + 1
		if stop > len(ops) {
			stop = len(ops)
		}
		aStart, bStart, aLen, bLen := ops[start].ai+1, ops[start].bi+1, 0, 0
		for _, op := range ops[start:stop] {
			if op.kind != '+' {
				aLen++
			}
			if op.kind != '-' {
				bLen++
			}
		}
		if aLen == 0 {
			aStart--
		}
		if bLen == 0 {
			bStart--
		}
		fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", aStart, aLen, bStart, bLen)
		for _, op := range ops[start:stop] {
			out.WriteByte(op.kind)
			out.WriteString(op.text)
			out.WriteByte('\n')
			if op.noNewline {
				out.WriteString("\\ No newline at end of file\n")
			}
		}
		i = stop
	}
	return out.String()
}

type line struct {
	text      string
	noNewline bool
}

func splitLines(s string) []line {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, "\n")
	last := len(parts) - 1
	if parts[last] == "" {
		parts = parts[:last]
		last = -1
	}
	out := make([]line, len(parts))
	for i, p := range parts {
		out[i] = line{text: p, noNewline: i == last}
	}
	return out
}

type diffOp struct {
	kind      byte // ' ', '-', '+'
	text      string
	noNewline bool
	ai, bi    int // line index (0-based) in a and b before this op
}

// maxLCSCells bounds the table of the longest common subsequence.
const maxLCSCells = 4 << 20

func diffLines(a, b []line) []diffOp {
	var ops []diffOp
	ai, bi := 0, 0
	keep := func(l line) {
		ops = append(ops, diffOp{' ', l.text, l.noNewline, ai, bi})
		ai++
		bi++
	}
	del := func(l line) { ops = append(ops, diffOp{'-', l.text, l.noNewline, ai, bi}); ai++ }
	add := func(l line) { ops = append(ops, diffOp{'+', l.text, l.noNewline, ai, bi}); bi++ }

	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	for _, l := range a[:pre] {
		keep(l)
	}
	ma, mb := a[pre:len(a)-suf], b[pre:len(b)-suf]
	if len(ma)*len(mb) <= maxLCSCells {
		// lcs[i][j]: length of the LCS of ma[i:] and mb[j:].
		w := len(mb) + 1
		lcs := make([]int32, (len(ma)+1)*w)
		for i := len(ma) - 1; i >= 0; i-- {
			for j := len(mb) - 1; j >= 0; j-- {
				if ma[i] == mb[j] {
					lcs[i*w+j] = lcs[(i+1)*w+j+1] + 1
				} else {
					lcs[i*w+j] = max(lcs[(i+1)*w+j], lcs[i*w+j+1])
				}
			}
		}
		i, j := 0, 0
		for i < len(ma) && j < len(mb) {
			switch {
			case ma[i] == mb[j]:
				keep(ma[i])
				i++
				j++
			case lcs[(i+1)*w+j] >= lcs[i*w+j+1]:
				del(ma[i])
				i++
			default:
				add(mb[j])
				j++
			}
		}
		for ; i < len(ma); i++ {
			del(ma[i])
		}
		for ; j < len(mb); j++ {
			add(mb[j])
		}
	} else {
		for _, l := range ma {
			del(l)
		}
		for _, l := range mb {
			add(l)
		}
	}
	for _, l := range a[len(a)-suf:] {
		keep(l)
	}
	return ops
}
