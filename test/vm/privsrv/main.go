// Command privsrv is a stdio MCP server for the VM tests of privileged
// backends (test/vm, docs/architecture.md section 5.7.1). Like
// mcp-server-zypp it changes the system through the package manager: its
// tools run rpm, which SELinux runs in rpm_t. Tools:
//
//	install_rpm {path}   rpm -i --nodeps <path>
//	remove_rpm  {name}   rpm -e <name>
//	hold        {seconds, marker}
//	                     waits, then writes marker; ignores cancellation,
//	                     as a running RPM transaction must
//	read_credential {name}  $CREDENTIALS_DIRECTORY/name
//	list_credentials        the entries of /run/credentials
//	read_file   {path}   a file's content (what the sandbox lets it see)
//
// With -http ADDR it is instead an MCP server over Streamable HTTP
// (http.go).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  any             `json:"result,omitempty"`
}

func schema(props ...string) map[string]any {
	p := map[string]any{}
	for _, name := range props {
		p[name] = map[string]any{"type": "string"}
	}
	return map[string]any{"type": "object", "properties": p}
}

var tools = []map[string]any{
	{"name": "install_rpm", "inputSchema": schema("path")},
	{"name": "remove_rpm", "inputSchema": schema("name")},
	{"name": "hold", "inputSchema": schema("seconds", "marker")},
	{"name": "read_credential", "inputSchema": schema("name")},
	{"name": "list_credentials", "inputSchema": schema()},
	{"name": "read_file", "inputSchema": schema("path")},
}

func text(s string, isErr bool) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": s}}, "isError": isErr}
}

func call(name string, args map[string]string) map[string]any {
	switch name {
	case "install_rpm", "remove_rpm":
		cmd := exec.Command("/usr/bin/rpm", "-i", "--nodeps", args["path"])
		if name == "remove_rpm" {
			cmd = exec.Command("/usr/bin/rpm", "-e", args["name"])
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			return text(fmt.Sprintf("%s: %v\n%s", name, err, out), true)
		}
		return text(name+" done\n"+string(out), false)
	case "hold":
		var secs int
		_, _ = fmt.Sscan(args["seconds"], &secs)
		time.Sleep(time.Duration(secs) * time.Second)
		if err := os.WriteFile(args["marker"], []byte("held\n"), 0o644); err != nil {
			return text(err.Error(), true)
		}
		return text("held", false)
	case "read_credential":
		b, err := os.ReadFile(filepath.Join(os.Getenv("CREDENTIALS_DIRECTORY"), args["name"]))
		if err != nil {
			return text(err.Error(), true)
		}
		return text("credential: "+strings.TrimSpace(string(b)), false)
	case "list_credentials":
		entries, err := os.ReadDir("/run/credentials")
		if err != nil {
			return text(err.Error(), true)
		}
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		return text("units: "+strings.Join(names, " "), false)
	case "read_file":
		b, err := os.ReadFile(args["path"])
		if err != nil {
			return text(err.Error(), true)
		}
		return text(string(b), false)
	}
	return text("unknown tool "+name, true)
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "-http" {
		if err := serveHTTP(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	in := bufio.NewScanner(os.Stdin)
	out := json.NewEncoder(os.Stdout)
	for in.Scan() {
		var m message
		if json.Unmarshal(in.Bytes(), &m) != nil || len(m.ID) == 0 {
			continue // notifications (cancellation is ignored) and junk
		}
		var res any
		switch m.Method {
		case "initialize":
			res = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}},
				"serverInfo": map[string]any{"name": "privsrv"}}
		case "tools/list":
			res = map[string]any{"tools": tools}
		case "tools/call":
			var p struct {
				Name      string            `json:"name"`
				Arguments map[string]string `json:"arguments"`
			}
			_ = json.Unmarshal(m.Params, &p)
			res = call(p.Name, p.Arguments)
		default:
			res = map[string]any{}
		}
		_ = out.Encode(message{JSONRPC: "2.0", ID: m.ID, Result: res})
		fmt.Fprintln(os.Stderr, "privsrv:", m.Method, strings.TrimSpace(string(m.Params)))
	}
}
