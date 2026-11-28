package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"text/tabwriter"

	"github.com/sdrahn/mcp-gateway/internal/router"
)

const instancesUsage = `usage: mcp-gateway-admin instances [options]           list the instances
       mcp-gateway-admin instances stop ID [options]   stop one

Lists the instances of the MCP servers you may manage (data.mcp.approvals:
your own; the approvers named for a server: its instances), with the
server, whom each serves and, with several replicas, the replica that runs
it. In a cluster, where there is no Cockpit, it is what the console's
Servers page shows (--gateway, or kubectl exec into the gateway's
container).

"instances stop ID" stops an instance, as if it had gone idle: its
sessions end, and the next call starts a new one. ID is the id the list
shows, or any prefix of it that names one instance. An instance of a
privileged server is not stopped during a call.

Exit status: 0; 1 when the instance is not yours to stop or there is none
with that id (the two read alike), it is busy, or the question was
answered no; 2 for wrong usage; 3 when the gateway does not answer.

Options:
`

// serverRows is the part of GET /v1/servers the command reads.
type serverRows struct {
	Name      string                `json:"name"`
	Instances []router.InstanceInfo `json:"instances"`
}

func runInstances(args []string, stdout, stderr io.Writer) int {
	f := newAdminFlags("instances", instancesUsage, stderr).withGateway()
	yes := f.fs.Bool("yes", false, "stop without asking")
	words, rc := f.parse(args)
	if rc >= 0 {
		return rc
	}
	switch {
	case len(words) == 0:
	case words[0] == "stop" && len(words) == 2:
	default:
		f.fs.Usage()
		return exitUsage
	}
	cc, err := f.client()
	if err != nil {
		say(stderr, "mcp-gateway-admin:", err)
		return exitUnreachable
	}
	var servers []serverRows
	raw, rc := cc.list(stderr, "/v1/servers", &servers)
	if rc != 0 {
		return rc
	}
	var list []router.InstanceInfo
	for _, s := range servers {
		list = append(list, s.Instances...)
	}
	ids := make([]string, len(list))
	for i, in := range list {
		ids[i] = in.ID
	}
	// Instance ids are short and readable (server, principal, number;
	// another replica's with its name): shown whole.
	short := ids
	if len(words) == 0 {
		if *f.json {
			_, _ = stdout.Write(raw)
			return 0
		}
		printInstances(stdout, list, short)
		return 0
	}
	i, rc := pick(stderr, ids, words[1], "instance")
	if rc != 0 {
		return rc
	}
	in := list[i]
	if !*yes && !confirm(stderr, fmt.Sprintf("Stop the instance %s of %s for %s (%d sessions)?", short[i], in.Server, orDash(in.Sub), in.Sessions)) {
		say(stderr, "mcp-gateway-admin: not stopped (--yes stops without asking)")
		return exitRefused
	}
	switch status, msg, err := cc.do(http.MethodDelete, "/v1/instances/"+url.PathEscape(in.ID), nil); {
	case err != nil:
		say(stderr, "mcp-gateway-admin:", err)
		return exitUnreachable
	case status == http.StatusNoContent:
		sayf(stdout, "stopped %s (%s for %s)", short[i], in.Server, orDash(in.Sub))
		return 0
	case status == http.StatusNotFound:
		sayf(stderr, "mcp-gateway-admin: no such instance: %s", words[1])
		return exitRefused
	default:
		sayf(stderr, "mcp-gateway-admin: stopping %s: %s", short[i], msg)
		return exitRefused
	}
}

func printInstances(w io.Writer, list []router.InstanceInfo, short []string) {
	if len(list) == 0 {
		say(w, "no instances")
		return
	}
	replicas := false
	for _, in := range list {
		replicas = replicas || in.Replica != ""
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	header := "SERVER\tUSER\tSTARTED\tSESSIONS\t"
	if replicas {
		header += "REPLICA\t"
	}
	_, _ = fmt.Fprintln(tw, header+"ID")
	for i, in := range list {
		sessions := fmt.Sprint(in.Sessions)
		if in.Busy {
			sessions += " (busy)"
		}
		row := fmt.Sprintf("%s\t%s\t%s\t%s\t", in.Server, orDash(in.Sub), clock(in.Started), sessions)
		if replicas {
			row += orDash(in.Replica) + "\t"
		}
		_, _ = fmt.Fprintln(tw, row+short[i])
	}
	_ = tw.Flush()
}
