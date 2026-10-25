package main

// The commands approvals and grants (docs/architecture.md, section 11,
// step 39 stage B): pending approvals listed, shown and decided, and
// grants listed and revoked, through the control API as the user who runs
// them, so that the approver rules (data.mcp.approvals) decide, as for
// Cockpit. Over SSH this is a way to decide without Cockpit (D21).

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/broker"
	"github.com/sdrahn/mcp-gateway/internal/pep"
)

const approvalsUsage = `usage: mcp-gateway-admin approvals [options]                 list the pending approvals
       mcp-gateway-admin approvals show ID [options]         show one, with its arguments
       mcp-gateway-admin approvals approve ID [options]      approve one
       mcp-gateway-admin approvals deny ID [options]         deny one
       mcp-gateway-admin approvals watch [options]           follow them as they come and go

Lists the approvals waiting for a decision that you may decide on (your
own, and others' as the approver rules allow; root: all), as Cockpit's
Approvals tab does. ID is the id the list shows (a-...), or any prefix of
it that names one approval.

"approvals approve ID" asks before approving (--yes does not) and grants
the scope --scope names: one the approval offers ("once", "session", or
a duration such as "1h"); without --scope, "once" if offered, else the
only one offered. The waiting call then runs; one that went away finds
the decision when its agent tries again. "approvals deny ID" denies.
Decisions are audited as made on the command line.

"approvals watch" prints the pending approvals, then each new one and
each decided or expired, until interrupted.

Exit status: 0; 1 when the approval is not yours to decide or there is
none with that id (the two read alike), the scope is not offered, or the
question was answered no; 2 for wrong usage; 3 when the gateway does not
answer (or, for watch, stops answering).

Options:
`

const grantsUsage = `usage: mcp-gateway-admin grants [options]             list the grants
       mcp-gateway-admin grants revoke ID [options]   revoke one

Lists the grants approvals left that you may see and revoke (your own,
and others' as the approver rules allow; root: all): who may call which
tool without being asked again, until when.

"grants revoke ID" revokes one after a question (--yes does not ask): the
next such call asks for approval again; calls already running finish.
ID is the id the list shows (g-...), or any prefix of it that names one
grant.

Exit status: 0; 1 when the grant is not yours to revoke or there is none
with that id (the two read alike), or the question was answered no; 2 for
wrong usage; 3 when the gateway does not answer.

Options:
`

func runApprovals(args []string, stdout, stderr io.Writer) int {
	f := newAdminFlags("approvals", approvalsUsage, stderr)
	yes := f.fs.Bool("yes", false, "approve without asking")
	scope := f.fs.String("scope", "", `the scope to approve with ("once", "session", a duration such as "1h")`)
	words, rc := f.parse(args)
	if rc >= 0 {
		return rc
	}
	switch {
	case len(words) == 0:
	case len(words) == 1 && words[0] == "watch":
	case len(words) == 2 && (words[0] == "show" || words[0] == "approve" || words[0] == "deny"):
	default:
		f.fs.Usage()
		return exitUsage
	}
	cc, err := newControlClient(*f.socket)
	if err != nil {
		say(stderr, "mcp-gateway-admin:", err)
		return exitUnreachable
	}
	if len(words) == 1 {
		return cc.watch(stdout, stderr, *f.json)
	}
	var list []broker.Pending
	raw, rc := cc.list(stderr, "/v1/approvals", &list)
	if rc != 0 {
		return rc
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Created.Before(list[j].Created) })
	ids := make([]string, len(list))
	for i, p := range list {
		ids[i] = p.ID
	}
	short := shortIDs(ids)
	if len(words) == 0 {
		if *f.json {
			_, _ = stdout.Write(raw)
			return 0
		}
		printApprovals(stdout, list, short)
		return 0
	}
	i, rc := pick(stderr, ids, words[1], "approval")
	if rc != 0 {
		return rc
	}
	p := list[i]
	switch words[0] {
	case "show":
		if *f.json {
			data, _ := json.MarshalIndent(p, "", "  ")
			say(stdout, string(data))
			return 0
		}
		printApproval(stdout, p)
		return 0
	case "deny":
		return cc.decide(stdout, stderr, p, short[i], "deny", "")
	}
	s, ok := pickScope(p.Scopes, *scope)
	if !ok {
		if *scope != "" {
			sayf(stderr, "mcp-gateway-admin: %s offers the scopes %s, not %q", short[i], strings.Join(p.Scopes, ", "), *scope)
		} else {
			sayf(stderr, "mcp-gateway-admin: %s offers the scopes %s: name one with --scope", short[i], strings.Join(p.Scopes, ", "))
		}
		return exitRefused
	}
	if !*yes && !confirm(stderr, fmt.Sprintf("Approve %s for %s (%s, scope %s)?", target(p), p.Principal.Sub, short[i], s)) {
		say(stderr, "mcp-gateway-admin: not approved (--yes approves without asking)")
		return exitRefused
	}
	return cc.decide(stdout, stderr, p, short[i], "approve", s)
}

// pickScope returns the scope to approve with: asked if offered; without
// one, "once" if offered, else the only one offered.
func pickScope(offered []string, asked string) (string, bool) {
	switch {
	case asked != "":
		return asked, slices.Contains(offered, asked)
	case slices.Contains(offered, "once"):
		return "once", true
	case len(offered) == 1:
		return offered[0], true
	}
	return "", false
}

// decide posts the decision on p.
func (cc *controlClient) decide(stdout, stderr io.Writer, p broker.Pending, short, decision, scope string) int {
	body, _ := json.Marshal(map[string]string{"decision": decision, "scope": scope, "via": "cli"})
	status, msg, err := cc.do(http.MethodPost, "/v1/approvals/"+url.PathEscape(p.ID), body)
	switch {
	case err != nil:
		say(stderr, "mcp-gateway-admin:", err)
		return exitUnreachable
	case status == http.StatusOK || status == http.StatusNoContent:
		if decision == "deny" {
			sayf(stdout, "denied %s (%s for %s)", short, target(p), p.Principal.Sub)
		} else {
			sayf(stdout, "approved %s (%s for %s, scope %s)", short, target(p), p.Principal.Sub, scope)
		}
		if !p.Waiting {
			say(stdout, "no call is waiting: the agent's next attempt finds the decision")
		}
		return 0
	case status == http.StatusNotFound:
		sayf(stderr, "mcp-gateway-admin: no such approval: %s (decided or expired meanwhile?)", short)
		return exitRefused
	default:
		sayf(stderr, "mcp-gateway-admin: deciding %s: %s", short, msg)
		return exitRefused
	}
}

// watch follows /v1/events: the pending approvals, then their changes.
func (cc *controlClient) watch(stdout, stderr io.Writer, raw bool) int {
	req, err := http.NewRequest(http.MethodGet, "http://gateway/v1/events", nil)
	if err != nil {
		say(stderr, "mcp-gateway-admin:", err)
		return exitUnreachable
	}
	// The stream stays open: no overall timeout, as for the lists.
	client := &http.Client{Transport: cc.http.Transport}
	resp, err := client.Do(req)
	if err != nil {
		say(stderr, "mcp-gateway-admin:", cc.unreachable(err))
		return exitUnreachable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		sayf(stderr, "mcp-gateway-admin: /v1/events: %s", apiMessage(resp.StatusCode, data))
		return exitRefused
	}
	if !raw {
		say(stderr, "Watching the approvals you may decide on (Ctrl-C ends).")
	}
	known := map[string]broker.Pending{}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		if raw {
			say(stdout, data)
			continue
		}
		var ev struct {
			Type    string          `json:"type"`
			ID      string          `json:"id"`
			New     bool            `json:"new"`
			Pending *broker.Pending `json:"pending"`
			URL     string          `json:"url"`
		}
		if json.Unmarshal([]byte(data), &ev) != nil {
			continue
		}
		when := now().Local().Format("15:04:05")
		switch ev.Type {
		case "pending":
			if ev.Pending == nil {
				continue
			}
			p := *ev.Pending
			_, seen := known[p.ID]
			known[p.ID] = p
			waiting := ""
			if !p.Waiting {
				waiting = ", no call waiting"
			}
			verb := "pending"
			if seen {
				verb = "again"
			}
			sayf(stdout, "%s %s %s %s for %s (scopes %s; expires %s%s)", when, verb, p.ID, target(p), p.Principal.Sub,
				strings.Join(p.Scopes, ", "), clock(p.Expires), waiting)
		case "resolved":
			p, ok := known[ev.ID]
			delete(known, ev.ID)
			if ok {
				sayf(stdout, "%s gone    %s %s for %s (decided or expired)", when, ev.ID, target(p), p.Principal.Sub)
			} else {
				sayf(stdout, "%s gone    %s", when, ev.ID)
			}
		}
	}
	say(stderr, "mcp-gateway-admin: the gateway ended the stream (stopped or restarted?)")
	return exitUnreachable
}

func runGrants(args []string, stdout, stderr io.Writer) int {
	f := newAdminFlags("grants", grantsUsage, stderr)
	yes := f.fs.Bool("yes", false, "revoke without asking")
	words, rc := f.parse(args)
	if rc >= 0 {
		return rc
	}
	switch {
	case len(words) == 0:
	case words[0] == "revoke" && len(words) == 2:
	default:
		f.fs.Usage()
		return exitUsage
	}
	cc, err := newControlClient(*f.socket)
	if err != nil {
		say(stderr, "mcp-gateway-admin:", err)
		return exitUnreachable
	}
	var list []pep.Grant
	raw, rc := cc.list(stderr, "/v1/grants", &list)
	if rc != 0 {
		return rc
	}
	ids := make([]string, len(list))
	for i, g := range list {
		ids[i] = g.ID
	}
	short := shortIDs(ids)
	if len(words) == 0 {
		if *f.json {
			_, _ = stdout.Write(raw)
			return 0
		}
		printGrants(stdout, list, short)
		return 0
	}
	i, rc := pick(stderr, ids, words[1], "grant")
	if rc != 0 {
		return rc
	}
	g := list[i]
	if !*yes && !confirm(stderr, fmt.Sprintf("Revoke the grant of %s/%s for %s (%s)?", g.Server, g.Tool, g.Sub, short[i])) {
		say(stderr, "mcp-gateway-admin: not revoked (--yes revokes without asking)")
		return exitRefused
	}
	switch status, msg, err := cc.do(http.MethodDelete, "/v1/grants/"+url.PathEscape(g.ID)+"?via=cli", nil); {
	case err != nil:
		say(stderr, "mcp-gateway-admin:", err)
		return exitUnreachable
	case status == http.StatusNoContent:
		sayf(stdout, "revoked %s (%s/%s for %s)", short[i], g.Server, g.Tool, g.Sub)
		return 0
	case status == http.StatusNotFound:
		sayf(stderr, "mcp-gateway-admin: no such grant: %s", words[1])
		return exitRefused
	default:
		sayf(stderr, "mcp-gateway-admin: revoking %s: %s", short[i], msg)
		return exitRefused
	}
}

// target is what an approval is for: server/tool, or the action and
// name for other requests.
func target(p broker.Pending) string {
	if p.Action == "" || p.Action == "tools.call" {
		return p.Server + "/" + p.Name
	}
	return p.Action + " " + p.Server + "/" + p.Name
}

func printApprovals(w io.Writer, list []broker.Pending, short []string) {
	if len(list) == 0 {
		say(w, "no pending approvals")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "USER\tCALL\tCLIENT\tSCOPES\tSINCE\tEXPIRES\tWAITING\tID")
	for i, p := range list {
		waiting := "yes"
		if !p.Waiting {
			waiting = "no"
		}
		client := orDash(strings.TrimSpace(p.Principal.Client.Name + " " + p.Principal.Client.Version))
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", orDash(p.Principal.Sub), target(p), client,
			strings.Join(p.Scopes, ","), ago(p.Created), until(p.Expires), waiting, short[i])
	}
	_ = tw.Flush()
}

func printApproval(w io.Writer, p broker.Pending) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	row := func(k, v string) { _, _ = fmt.Fprintf(tw, "%s\t%s\n", k, v) }
	row("ID", p.ID)
	row("User", orDash(p.Principal.Sub))
	row("Call", target(p))
	row("Client", orDash(strings.TrimSpace(p.Principal.Client.Name+" "+p.Principal.Client.Version)))
	row("Asked via", string(p.Channel))
	row("Scopes", strings.Join(p.Scopes, ", "))
	row("Since", clock(p.Created)+" ("+ago(p.Created)+")")
	row("Expires", clock(p.Expires)+" ("+until(p.Expires)+")")
	if p.Waiting {
		row("Waiting", "yes, the call waits for the decision")
	} else {
		row("Waiting", "no: the agent's next attempt finds the decision")
	}
	if p.Prompt != "" {
		row("Prompt", p.Prompt)
	}
	_ = tw.Flush()
	if len(p.Args) > 0 {
		data, _ := json.MarshalIndent(p.Args, "  ", "  ")
		say(w, "Arguments:")
		say(w, "  "+string(data))
	} else {
		say(w, "Arguments: none (or left out by policy)")
	}
}

func printGrants(w io.Writer, list []pep.Grant, short []string) {
	if len(list) == 0 {
		say(w, "no grants")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "USER\tCALL\tSCOPE\tEXPIRES\tAPPROVED BY\tID")
	for i, g := range list {
		exp := "-"
		if t, err := time.Parse(time.RFC3339, g.Expires); err == nil {
			exp = clock(t) + " (" + until(t) + ")"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s/%s\t%s\t%s\t%s\t%s\n", orDash(g.Sub), g.Server, g.Tool, g.Scope, exp,
			orDash(g.ApprovedBy), short[i])
	}
	_ = tw.Flush()
}

// until is how long until t, in its largest unit ("expired" once past).
func until(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := t.Sub(now())
	switch {
	case d <= 0:
		return "expired"
	case d < time.Minute:
		return "in " + fmt.Sprint(int(d/time.Second)) + "s"
	case d < time.Hour:
		return "in " + fmt.Sprint(int(d/time.Minute)) + "m"
	case d < 24*time.Hour:
		return "in " + fmt.Sprint(int(d/time.Hour)) + "h"
	}
	return "in " + fmt.Sprint(int(d/(24*time.Hour))) + "d"
}
