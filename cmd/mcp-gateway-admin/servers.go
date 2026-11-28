package main

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/sdrahn/mcp-gateway/internal/router"
)

const serversUsage = `usage: mcp-gateway-admin servers [options]

Lists the MCP servers the gateway serves: where each comes from (a server
file, or the cluster's Service it was discovered from with
server_discovery), how its instances are isolated, and how many of them
you may manage run. A server removed from the configuration whose
instances still run is listed as such. "instances" lists the instances.

Exit status: 0; 2 for wrong usage; 3 when the gateway does not answer.

Options:
`

// serverList is the part of GET /v1/servers the command reads.
type serverList struct {
	Name       string `json:"name"`
	Isolation  string `json:"isolation"`
	Privileged bool   `json:"privileged"`
	SignIn     bool   `json:"sign_in"`
	Removed    bool   `json:"removed"`
	Discovered *struct {
		Namespace string `json:"namespace"`
		Service   string `json:"service"`
	} `json:"discovered"`
	Instances []router.InstanceInfo `json:"instances"`
}

func runServers(args []string, stdout, stderr io.Writer) int {
	f := newAdminFlags("servers", serversUsage, stderr).withGateway()
	words, rc := f.parse(args)
	if rc >= 0 {
		return rc
	}
	if len(words) != 0 {
		f.fs.Usage()
		return exitUsage
	}
	cc, err := f.client()
	if err != nil {
		say(stderr, "mcp-gateway-admin:", err)
		return exitUnreachable
	}
	var servers []serverList
	raw, rc := cc.list(stderr, "/v1/servers", &servers)
	if rc != 0 {
		return rc
	}
	if *f.json {
		_, _ = stdout.Write(raw)
		return 0
	}
	printServers(stdout, servers)
	return 0
}

func printServers(w io.Writer, servers []serverList) {
	if len(servers) == 0 {
		say(w, "no servers")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SERVER\tFROM\tISOLATION\tINSTANCES")
	for _, s := range servers {
		from := "server file"
		switch {
		case s.Removed:
			from = "removed (its instances stop once their calls are answered)"
		case s.Discovered != nil:
			from = "Service " + s.Discovered.Namespace + "/" + s.Discovered.Service
		}
		isolation := orDash(s.Isolation)
		if s.Privileged {
			isolation += " (privileged)"
		}
		if s.SignIn {
			isolation += ", sign-in"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", s.Name, from, isolation, len(s.Instances))
	}
	_ = tw.Flush()
}
