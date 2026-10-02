package profile

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Denial is one SELinux denial (AVC from the kernel, USER_AVC from a
// userspace object manager such as D-Bus or systemd).
type Denial struct {
	Time       time.Time
	Source     string // source type
	Target     string // target type
	Class      string
	Perms      []string
	Comm       string
	Path       string // path= or name=
	Permissive bool
	User       bool // a USER_AVC
}

// Record is a SELINUX_ERR (e.g. a refused bounded or NNP transition): no
// allow rule fixes it, so it is reported as it is.
type Record struct {
	Time time.Time
	Text string
}

var (
	auditTime = regexp.MustCompile(`msg=audit\((\d+)\.(\d+):\d+\)`)
	avcPerms  = regexp.MustCompile(`avc:\s+denied\s+\{([^}]*)\}`)
	avcField  = regexp.MustCompile(`\b(scontext|tcontext|tclass|comm|path|name|permissive)=("[^"]*"|[^ ']+)`)
)

// Parse reads audit records (raw lines, one record per line) and returns
// the denials and SELINUX_ERR records at or after since.
func Parse(data []byte, since time.Time) ([]Denial, []Record) {
	var denials []Denial
	var errs []Record
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		t, ok := recordTime(line)
		if !ok || t.Before(since.Truncate(time.Second)) {
			continue
		}
		if strings.Contains(line, "type=SELINUX_ERR") {
			errs = append(errs, Record{Time: t, Text: line})
			continue
		}
		m := avcPerms.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		d := Denial{Time: t, Perms: strings.Fields(m[1]), User: strings.Contains(line, "type=USER_AVC")}
		// In a USER_AVC the denial is in msg='...'; fields after it
		// belong to the record (exe=, hostname=...), not the denial.
		rest := line[strings.Index(line, m[0]):]
		for _, f := range avcField.FindAllStringSubmatch(rest, -1) {
			v := strings.Trim(f[2], `"`)
			switch f[1] {
			case "scontext":
				d.Source = contextType(v)
			case "tcontext":
				d.Target = contextType(v)
			case "tclass":
				d.Class = v
			case "comm":
				d.Comm = v
			case "path":
				d.Path = v
			case "name":
				if d.Path == "" {
					d.Path = v
				}
			case "permissive":
				d.Permissive = v == "1"
			}
		}
		if d.Source != "" && d.Target != "" && d.Class != "" {
			denials = append(denials, d)
		}
	}
	return denials, errs
}

func recordTime(line string) (time.Time, bool) {
	m := auditTime.FindStringSubmatch(line)
	if m == nil {
		return time.Time{}, false
	}
	sec, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	ms, _ := strconv.ParseInt(m[2], 10, 64)
	return time.Unix(sec, ms*int64(time.Millisecond)), true
}

// contextType returns the type of a security context (user:role:type:level).
func contextType(ctx string) string {
	parts := strings.SplitN(ctx, ":", 4)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

// Involving returns the denials whose source or target is domain, and
// the SELINUX_ERR records that name it.
func Involving(denials []Denial, errs []Record, domain string) ([]Denial, []Record) {
	var d []Denial
	for _, x := range denials {
		if x.Source == domain || x.Target == domain {
			d = append(d, x)
		}
	}
	var e []Record
	for _, x := range errs {
		if strings.Contains(x.Text, ":"+domain+":") {
			e = append(e, x)
		}
	}
	return d, e
}

// ReadAudit returns the raw audit records of the last day: from the audit
// logs through ausearch where auditd runs, else from the journal (where
// the kernel's records go without auditd).
func ReadAudit(ctx context.Context) ([]byte, error) {
	if _, err := exec.LookPath("ausearch"); err == nil {
		out, err := exec.CommandContext(ctx, "ausearch", "--input-logs", "-m", "AVC,USER_AVC,SELINUX_ERR",
			"-ts", "yesterday", "--raw").Output()
		// ausearch exits 1 when nothing matches.
		if err == nil || len(out) > 0 {
			return out, nil
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return nil, nil
		}
	}
	return exec.CommandContext(ctx, "journalctl", "--no-pager", "-o", "cat", "--since", "-1d", "_TRANSPORT=audit").Output()
}

// Summary is one line per distinct denial, most frequent first.
func Summary(denials []Denial) []string {
	count := map[string]int{}
	for _, d := range denials {
		k := d.Source + " " + d.Target + ":" + d.Class + " { " + strings.Join(d.Perms, " ") + " }"
		if d.Path != "" {
			k += " " + d.Path
		}
		if d.Comm != "" {
			k += " (" + d.Comm + ")"
		}
		count[k]++
	}
	keys := make([]string, 0, len(count))
	for k := range count {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if count[keys[i]] != count[keys[j]] {
			return count[keys[i]] > count[keys[j]]
		}
		return keys[i] < keys[j]
	})
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = strconv.Itoa(count[k]) + "  " + k
	}
	return out
}
