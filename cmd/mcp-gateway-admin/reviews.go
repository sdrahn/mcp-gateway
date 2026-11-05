package main

// The command reviews: the calls policy marked for review after they ran
// (obligation "review"), listed, shown and judged through the control
// API as the user who runs it, so that the approver rules decide who may
// review, as for approvals.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/tabwriter"

	"github.com/sdrahn/mcp-gateway/internal/broker"
)

const reviewsUsage = `usage: mcp-gateway-admin reviews [options]                    list the calls to review
       mcp-gateway-admin reviews show ID [options]            show one, with its arguments
       mcp-gateway-admin reviews ok ID [options]              judge it fine
       mcp-gateway-admin reviews incident ID --reason TEXT    judge that it should not have run

Lists the calls that ran without asking anyone and that policy marked for
review afterwards (the obligation "review"), which you may review: as you
may decide on such a call's approval (your own, and others' as the
approver rules allow; root: all). Without --all, only those without a
verdict. ID is the id the list shows (r-...), or any prefix of it that
names one item.

A verdict replaces an earlier one and is audited (mcp-review). An
incident needs a reason. Judging your own call fine where only the
approver rule "self" lets you review it asks for your password (polkit)
in this terminal, as approving your own request does. With --gateway
URL, on that gateway, as signed in there (mcp-gateway-admin approvals
login --gateway URL). Items are kept for 7 days.

Exit status: 0; 1 when the item is not yours to review or there is none
with that id (the two read alike), an incident has no reason, or your
password was not given; 2 for wrong usage; 3 when the gateway does not
answer.

Options:
`

func runReviews(args []string, stdout, stderr io.Writer) int {
	f := newAdminFlags("reviews", reviewsUsage, stderr)
	all := f.fs.Bool("all", false, "list the items with a verdict too")
	reason := f.fs.String("reason", "", "why (required for an incident)")
	gateway := f.fs.String("gateway", "", "a gateway on another host, https://host:port (approvals login --gateway signs in)")
	words, rc := f.parse(args)
	if rc >= 0 {
		return rc
	}
	switch {
	case len(words) == 0:
	case len(words) == 2 && (words[0] == "show" || words[0] == "ok" || words[0] == "incident"):
	default:
		f.fs.Usage()
		return exitUsage
	}
	if len(words) == 2 && words[0] == "incident" && strings.TrimSpace(*reason) == "" {
		say(stderr, "mcp-gateway-admin: an incident needs a reason (--reason)")
		return exitUsage
	}
	cc, err := clientFor(*f.socket, *gateway)
	if err != nil {
		say(stderr, "mcp-gateway-admin:", err)
		if *gateway != "" {
			return exitRefused
		}
		return exitUnreachable
	}
	var list []broker.Review
	raw, rc := cc.list(stderr, "/v1/reviews", &list)
	if rc != 0 {
		return rc
	}
	ids := make([]string, len(list))
	for i, r := range list {
		ids[i] = r.ID
	}
	short := shortIDs(ids)
	if len(words) == 0 {
		if *f.json {
			_, _ = stdout.Write(raw)
			return 0
		}
		printReviews(stdout, list, short, *all)
		return 0
	}
	i, rc := pick(stderr, ids, words[1], "review")
	if rc != 0 {
		return rc
	}
	r := list[i]
	if words[0] == "show" {
		if *f.json {
			data, _ := json.MarshalIndent(r, "", "  ")
			say(stdout, string(data))
			return 0
		}
		printReview(stdout, r)
		return 0
	}
	return cc.judge(stdout, stderr, r, short[i], words[0], *reason)
}

// judge posts a verdict on r.
func (cc *controlClient) judge(stdout, stderr io.Writer, r broker.Review, short, verdict, reason string) int {
	body, _ := json.Marshal(map[string]string{"verdict": verdict, "reason": reason, "via": "cli"})
	if verdict == broker.VerdictOK && cc.remote == "" {
		// The gateway may ask polkit for the user's password (a verdict
		// on their own call), in this terminal.
		stop := startTTYAgent()
		defer stop()
		slow := *cc
		client := *cc.http
		client.Timeout = ownPasswordTimeout
		slow.http = &client
		cc = &slow
	}
	status, msg, err := cc.do(http.MethodPost, "/v1/reviews/"+url.PathEscape(r.ID), body)
	switch {
	case err != nil:
		say(stderr, "mcp-gateway-admin:", err)
		return exitUnreachable
	case status == http.StatusOK:
		sayf(stdout, "reviewed %s (%s/%s for %s): %s", short, r.Server, r.Name, r.Principal.Sub, verdict)
		return 0
	case status == http.StatusNotFound:
		sayf(stderr, "mcp-gateway-admin: no such review: %s (expired meanwhile?)", short)
		return exitRefused
	default:
		sayf(stderr, "mcp-gateway-admin: reviewing %s: %s", short, msg)
		return exitRefused
	}
}

func verdictText(v *broker.Verdict) string {
	if v == nil {
		return "-"
	}
	return v.Verdict + " (" + v.By + ")"
}

func printReviews(w io.Writer, list []broker.Review, short []string, all bool) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	n := 0
	for i, r := range list {
		if r.Verdict != nil && !all {
			continue
		}
		if n == 0 {
			_, _ = fmt.Fprintln(tw, "USER\tCALL\tRAN\tOUTCOME\tVERDICT\tUNTIL\tID")
		}
		n++
		_, _ = fmt.Fprintf(tw, "%s\t%s/%s\t%s\t%s\t%s\t%s\t%s\n", orDash(r.Principal.Sub), r.Server, r.Name, ago(r.Ran),
			r.Outcome, verdictText(r.Verdict), until(r.Expires), short[i])
	}
	_ = tw.Flush()
	if n == 0 {
		if all || len(list) == 0 {
			say(w, "no calls to review")
		} else {
			sayf(w, "no calls without a verdict (%d with one: --all lists them)", len(list))
		}
	}
}

func printReview(w io.Writer, r broker.Review) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	row := func(k, v string) { _, _ = fmt.Fprintf(tw, "%s\t%s\n", k, v) }
	row("ID", r.ID)
	row("User", orDash(r.Principal.Sub))
	row("Call", r.Server+"/"+r.Name)
	row("Client", orDash(strings.TrimSpace(r.Principal.Client.Name+" "+r.Principal.Client.Version)))
	row("Ran", clock(r.Ran)+" ("+ago(r.Ran)+")")
	outcome := r.Outcome
	if r.Error != "" {
		outcome += ": " + r.Error
	}
	row("Outcome", outcome)
	switch {
	case r.ApprovalID != "":
		row("Allowed by", "approval "+r.ApprovalID)
	case r.GrantID != "":
		row("Allowed by", "grant "+r.GrantID)
	default:
		row("Allowed by", "policy")
	}
	row("Decision", r.DecisionID)
	row("Review until", clock(r.Expires)+" ("+until(r.Expires)+")")
	if v := r.Verdict; v != nil {
		text := v.Verdict + " by " + v.By + ", " + clock(v.At)
		if v.Reason != "" {
			text += ": " + v.Reason
		}
		row("Verdict", text)
	}
	_ = tw.Flush()
	if len(r.Args) > 0 {
		data, _ := json.MarshalIndent(r.Args, "  ", "  ")
		say(w, "Arguments:")
		say(w, "  "+string(data))
	} else {
		say(w, "Arguments: not recorded (the policy's audit keeps a digest)")
	}
}
