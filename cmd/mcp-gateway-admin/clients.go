package main

// The commands clients and tasks (docs/architecture.md, section 11, step
// 35): the clients using the gateway and the agents' tasks, listed, ended
// and cancelled through the control API as the user who runs them, so
// that the API's rules (data.mcp.approvals.manage_session and
// manage_task) decide, as for Cockpit.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/router"
)

// Exit status of clients and tasks.
const (
	exitRefused     = 1 // a refusal, an unknown or ambiguous id, a question answered no
	exitUsage       = 2
	exitUnreachable = 3 // the gateway does not answer
)

// stdin answers the question of clients end; now is the time the lists
// count from. Tests replace both.
var (
	stdin io.Reader = os.Stdin
	now             = time.Now
)

const clientsUsage = `usage: mcp-gateway-admin clients [options]           list the clients
       mcp-gateway-admin clients end ID [options]    end a client

Lists the clients using the gateway that you may manage: your own, and
everyone's on the servers you approve for (administrators: all). A
session is a client connected to the gateway; an agent of MCP 2026-07-28
has no session and is listed for an hour after its last request.

"clients end ID" ends one after a question, as if its client had gone:
its calls are cancelled, its streams close, its session grants and
instances go. ID is the id the list shows, or any prefix of it that names
one client.

Exit status: 0; 1 when the client is not yours to end or there is none
with that id (the two read alike), or the question was answered no; 2 for
wrong usage; 3 when the gateway does not answer.

Options:
`

const tasksUsage = `usage: mcp-gateway-admin tasks [options]             list the tasks
       mcp-gateway-admin tasks cancel ID [options]   cancel a running task

Lists the agents' tasks you may manage (your own; administrators: all),
running ones and the ended ones the gateway keeps for their agents.

"tasks cancel ID" cancels a running task: its call is cancelled at its
server and the agent gets the task as cancelled. ID is the id the list
shows, or any prefix of it that names one task.

Exit status: 0; 1 when the task is not yours to cancel, there is none with
that id (the two read alike) or it has ended; 2 for wrong usage; 3 when
the gateway does not answer.

Options:
`

// adminFlags are the options clients and tasks share.
type adminFlags struct {
	fs     *flag.FlagSet
	json   *bool
	socket *string
}

func newAdminFlags(name, usageText string, stderr io.Writer) adminFlags {
	fs := flag.NewFlagSet("mcp-gateway-admin "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprint(stderr, usageText)
		fs.PrintDefaults()
	}
	return adminFlags{fs: fs,
		json:   fs.Bool("json", false, "print the list as the control API's JSON"),
		socket: fs.String("socket", "", "the gateway's control socket (default: approvals.control_socket of gateway.yaml)")}
}

// parse parses args with the options anywhere among the words, as in
// "clients end ID --yes"; after "--" all are words (config set KEY -- -1s).
// It returns the words, or the exit status.
func (f adminFlags) parse(args []string) ([]string, int) {
	var words []string
	for {
		if len(args) > 0 && args[0] == "--" {
			return append(words, args[1:]...), -1
		}
		if err := f.fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, 0
			}
			return nil, exitUsage
		}
		args = f.fs.Args()
		if len(args) == 0 {
			return words, -1
		}
		words, args = append(words, args[0]), args[1:]
	}
}

func runClients(args []string, stdout, stderr io.Writer) int {
	f := newAdminFlags("clients", clientsUsage, stderr)
	yes := f.fs.Bool("yes", false, "end without asking")
	words, rc := f.parse(args)
	if rc >= 0 {
		return rc
	}
	switch {
	case len(words) == 0:
	case words[0] == "end" && len(words) == 2:
	default:
		f.fs.Usage()
		return exitUsage
	}
	cc, err := newControlClient(*f.socket)
	if err != nil {
		say(stderr, "mcp-gateway-admin:", err)
		return exitUnreachable
	}
	var list []router.SessionInfo
	raw, rc := cc.list(stderr, "/v1/sessions", &list)
	if rc != 0 {
		return rc
	}
	ids := make([]string, len(list))
	for i, c := range list {
		ids[i] = c.ID
	}
	short := shortIDs(ids)
	if len(words) == 0 {
		if *f.json {
			_, _ = stdout.Write(raw)
			return 0
		}
		printClients(stdout, list, short)
		return 0
	}
	i, rc := pick(stderr, ids, words[1], "client")
	if rc != 0 {
		return rc
	}
	c := list[i]
	if !*yes && !confirm(stderr, fmt.Sprintf("End the client %s of %s on %s (%s)?", clientName(c), c.Sub, c.Endpoint, short[i])) {
		say(stderr, "mcp-gateway-admin: not ended (--yes ends without asking)")
		return exitRefused
	}
	switch status, msg, err := cc.do(http.MethodDelete, "/v1/sessions/"+url.PathEscape(c.ID), nil); {
	case err != nil:
		say(stderr, "mcp-gateway-admin:", err)
		return exitUnreachable
	case status == http.StatusNoContent:
		sayf(stdout, "ended %s (%s of %s)", short[i], clientName(c), c.Sub)
		return 0
	case status == http.StatusNotFound:
		sayf(stderr, "mcp-gateway-admin: no such client: %s", words[1])
		return exitRefused
	default:
		sayf(stderr, "mcp-gateway-admin: ending %s: %s", short[i], msg)
		return exitRefused
	}
}

func runTasks(args []string, stdout, stderr io.Writer) int {
	f := newAdminFlags("tasks", tasksUsage, stderr)
	words, rc := f.parse(args)
	if rc >= 0 {
		return rc
	}
	switch {
	case len(words) == 0:
	case words[0] == "cancel" && len(words) == 2:
	default:
		f.fs.Usage()
		return exitUsage
	}
	cc, err := newControlClient(*f.socket)
	if err != nil {
		say(stderr, "mcp-gateway-admin:", err)
		return exitUnreachable
	}
	var list []router.TaskInfo
	raw, rc := cc.list(stderr, "/v1/tasks", &list)
	if rc != 0 {
		return rc
	}
	ids := make([]string, len(list))
	for i, t := range list {
		ids[i] = t.ID
	}
	short := shortIDs(ids)
	if len(words) == 0 {
		if *f.json {
			_, _ = stdout.Write(raw)
			return 0
		}
		printTasks(stdout, list, short)
		return 0
	}
	i, rc := pick(stderr, ids, words[1], "task")
	if rc != 0 {
		return rc
	}
	t := list[i]
	switch status, msg, err := cc.do(http.MethodPost, "/v1/tasks/"+url.PathEscape(t.ID)+"/cancel", nil); {
	case err != nil:
		say(stderr, "mcp-gateway-admin:", err)
		return exitUnreachable
	case status == http.StatusNoContent:
		sayf(stdout, "cancelled %s (%s %s of %s)", short[i], t.Server, t.Tool, t.Sub)
		return 0
	case status == http.StatusNotFound:
		sayf(stderr, "mcp-gateway-admin: no such task: %s", words[1])
		return exitRefused
	default:
		sayf(stderr, "mcp-gateway-admin: cancelling %s: %s", short[i], msg)
		return exitRefused
	}
}

func printClients(w io.Writer, list []router.SessionInfo, short []string) {
	if len(list) == 0 {
		say(w, "no clients")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "USER\tCLIENT\tMCP\tENDPOINT\tSINCE\tACTIVE\tID")
	for i, c := range list {
		mcp := c.Protocol
		if c.Capped != "" {
			mcp += " (capped)"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", orDash(c.Sub), clientName(c), orDash(mcp),
			orDash(c.Endpoint), clock(c.Started), ago(c.LastActive), short[i])
	}
	_ = tw.Flush()
}

func printTasks(w io.Writer, list []router.TaskInfo, short []string) {
	if len(list) == 0 {
		say(w, "no tasks")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SERVER\tTOOL\tUSER\tSTARTED\tSTATE\tID")
	for i, t := range list {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", t.Server, t.Tool, orDash(t.Sub), clock(t.Created),
			strings.ReplaceAll(t.Status, "_", " "), short[i])
	}
	_ = tw.Flush()
}

func clientName(c router.SessionInfo) string {
	return orDash(strings.TrimSpace(c.Client.Name + " " + c.Client.Version))
}

// clock is a time of today as 15:04, of another day with its date.
func clock(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	t, n := t.Local(), now().Local()
	if t.YearDay() == n.YearDay() && t.Year() == n.Year() {
		return t.Format("15:04")
	}
	return t.Format("2006-01-02 15:04")
}

// ago is how long ago t was, in its largest unit.
func ago(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := now().Sub(t)
	switch {
	case d < time.Second:
		return "now"
	case d < time.Minute:
		return strconv.Itoa(int(d/time.Second)) + "s ago"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + "m ago"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + "h ago"
	}
	return strconv.Itoa(int(d/(24*time.Hour))) + "d ago"
}

// shortIDLen is how much of an id the lists show at least: 8 characters,
// after the "agent-" of an agent's.
const shortIDLen = 8

// shortIDs shortens each id to its first shortIDLen characters, or more
// where that would not tell it from another of ids.
func shortIDs(ids []string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		n := shortIDLen
		if strings.HasPrefix(id, "agent-") {
			n += len("agent-")
		}
		for ; n < len(id); n++ {
			unique := true
			for j, other := range ids {
				if j != i && strings.HasPrefix(other, id[:n]) {
					unique = false
					break
				}
			}
			if unique {
				break
			}
		}
		out[i] = id[:min(n, len(id))]
	}
	return out
}

// pick returns the index of the id that prefix names, or reports none or
// several (what: "client", "task").
func pick(stderr io.Writer, ids []string, prefix, what string) (int, int) {
	var found []int
	for i, id := range ids {
		if id == prefix {
			return i, 0
		}
		if strings.HasPrefix(id, prefix) {
			found = append(found, i)
		}
	}
	switch len(found) {
	case 1:
		return found[0], 0
	case 0:
		sayf(stderr, "mcp-gateway-admin: no such %s: %s", what, prefix)
	default:
		sayf(stderr, "mcp-gateway-admin: %s names %d %ss; give more of the id", prefix, len(found), what)
	}
	return -1, exitRefused
}

// confirm asks question on stderr and reads the answer from stdin: yes
// only for "y" or "yes".
func confirm(stderr io.Writer, question string) bool {
	_, _ = fmt.Fprint(stderr, question+" [y/N] ")
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && line == "" {
		say(stderr)
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

// controlClient talks to the gateway's control API as the user who runs
// the command: the kernel names the caller to the gateway.
type controlClient struct {
	// base is where the API's paths start: the socket's, or with remote
	// (--gateway, remote.go) a gateway's approval API.
	base, remote string
	sock         string
	// group is socket_group of gateway.yaml, for the message when the
	// socket cannot be looked at.
	group string
	http  *http.Client
}

// newControlClient connects to sock, or to the control socket of the
// gateway's configuration.
func newControlClient(sock string) (*controlClient, error) {
	group := ""
	gw, _, err := config.Resolve("")
	if err == nil {
		group = gw.SocketGroup
	}
	if sock == "" {
		sock = config.DefaultControl
		if err == nil {
			sock = gw.Approvals.ControlSocket
		}
		if sock == "-" {
			return nil, errors.New("the gateway's control API is off (approvals.control_socket: \"-\" in gateway.yaml)")
		}
	}
	return &controlClient{base: "http://gateway", sock: sock, group: group, http: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}}, nil
}

// do sends a request; it returns the status and, for an error status, the
// API's message. An error is the gateway not answering.
func (cc *controlClient) do(method, path string, body []byte) (int, string, error) {
	status, data, err := cc.request(method, path, body)
	if err != nil || status < 300 {
		return status, "", err
	}
	return status, cc.message(status, data), nil
}

// message is the API's error message, or what to do when a remote
// gateway does not take the sign-in.
func (cc *controlClient) message(status int, data []byte) string {
	if cc.remote != "" && status == http.StatusUnauthorized {
		return signedOut(cc.remote)
	}
	return apiMessage(status, data)
}

// apiMessage is the message of the API's error answer.
func apiMessage(status int, data []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &e) != nil || e.Error == "" {
		return http.StatusText(status)
	}
	return e.Error
}

func (cc *controlClient) request(method, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(method, cc.base+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := cc.http.Do(req)
	if err != nil {
		return 0, nil, cc.unreachable(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return 0, nil, cc.unreachable(err)
	}
	return resp.StatusCode, data, nil
}

// list gets a list into v; it returns the JSON, or the exit status.
func (cc *controlClient) list(stderr io.Writer, path string, v any) ([]byte, int) {
	status, data, err := cc.request(http.MethodGet, path, nil)
	if err != nil {
		say(stderr, "mcp-gateway-admin:", err)
		return nil, exitUnreachable
	}
	if status != http.StatusOK {
		sayf(stderr, "mcp-gateway-admin: %s: %s", path, cc.message(status, data))
		return nil, exitRefused
	}
	if err := json.Unmarshal(data, v); err != nil {
		sayf(stderr, "mcp-gateway-admin: %s: %v", path, err)
		return nil, exitRefused
	}
	return data, 0
}

// unreachable says why the gateway does not answer and what to do.
func (cc *controlClient) unreachable(err error) error {
	if cc.remote != "" {
		return remoteUnreachable(cc.remote, err)
	}
	switch {
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		group := "the socket's group"
		if cc.group != "" {
			group = "the group " + cc.group
		}
		if fi, serr := os.Stat(cc.sock); serr == nil {
			if st, ok := fi.Sys().(*syscall.Stat_t); ok {
				if g, gerr := user.LookupGroupId(strconv.FormatUint(uint64(st.Gid), 10)); gerr == nil {
					group = "the group " + g.Name
				}
			}
		}
		return fmt.Errorf("no access to the gateway's control socket %s: it is for %s (add the user to it and log in again) and root", cc.sock, group)
	case errors.Is(err, syscall.ENOENT), errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Errorf("the gateway does not answer at %s: is it running? (systemctl status mcp-gateway.service)", cc.sock)
	}
	return fmt.Errorf("the gateway does not answer at %s: %w", cc.sock, err)
}
