// Command mcp-server-fs is an MCP server for files, run by mcp-gateway as
// the server "fs" (package mcp-gateway-fs-server). It speaks MCP on
// stdin/stdout and works in the directories given with --root, usually
// the user's home directory:
//
//   - reading: read_text_file, read_media_file, read_multiple_files,
//     list_directory, list_directory_with_sizes, directory_tree,
//     search_files, get_file_info, list_allowed_directories;
//   - changing: write_file, edit_file, create_directory, move_file,
//     delete_file (not offered with --read-only);
//   - older names kept: read_file, list_dir;
//   - the files in the directories as resources, a summarize_file prompt.
//
// The tool names and arguments follow the reference filesystem server
// of the MCP project, so that agents know them. Who may call which tool
// on which path is the gateway's policy; the server only keeps every
// operation inside the directories, through an os.Root each, so that a
// symbolic link pointing out of them is refused (docs/architecture.md,
// decision D13). Writes replace a file at once (temporary file and
// rename), reads and writes are bounded, and long searches end when the
// client cancels them.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sdrahn/mcp-gateway/internal/version"
)

const serverName = "mcp-server-fs"

var serverVersion = version.Version

type rootFlags []string

func (r *rootFlags) String() string     { return strings.Join(*r, ",") }
func (r *rootFlags) Set(v string) error { *r = append(*r, v); return nil }

func main() {
	var roots rootFlags
	flag.Var(&roots, "root", "a directory the tools work in (repeatable; default: the current directory); "+
		"relative paths in calls are relative to the first")
	readOnly := flag.Bool("read-only", false, "offer only the tools that read")
	about := flag.String("instructions", "", "what the files are, for the client's model (opens the server's instructions)")
	maxRead := flag.Int64("max-read", 10<<20, "bytes one call may read (summed over read_multiple_files)")
	maxWrite := flag.Int64("max-write", 10<<20, "bytes one call may write")
	maxEntries := flag.Int("max-entries", 10000, "entries a listing, tree or search returns at most")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [options]\n\nAn MCP server for files, on stdin/stdout.\n\n", serverName)
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println(serverName, serverVersion)
		return
	}
	if flag.NArg() > 0 {
		flag.Usage()
		os.Exit(2)
	}
	if *maxRead <= 0 || *maxWrite <= 0 || *maxEntries <= 0 {
		fmt.Fprintln(os.Stderr, serverName+": the limits must be positive")
		os.Exit(2)
	}
	if len(roots) == 0 {
		roots = rootFlags{"."}
	}
	s := &fileServer{readOnly: *readOnly, about: *about, maxRead: *maxRead, maxWrite: *maxWrite, maxEntries: *maxEntries}
	for _, r := range roots {
		abs, err := filepath.Abs(r)
		if err != nil {
			fmt.Fprintln(os.Stderr, serverName+":", err)
			os.Exit(2)
		}
		s.dirs = append(s.dirs, &allowed{path: abs})
	}
	// A log line on stderr, which goes to the journal, never on the MCP
	// connection.
	mode := ""
	if s.readOnly {
		mode = " (read-only)"
	}
	if ro := s.readOnlyDirs(); len(ro) > 0 && !s.readOnly {
		mode += " (on a read-only file system: " + strings.Join(ro, ", ") + ")"
	}
	fmt.Fprintf(os.Stderr, "%s: serving %s%s\n", serverName, strings.Join(s.dirPaths(), ", "), mode)

	// A message carries at most a write's content, JSON-escaped (up to
	// 6 bytes per byte for control characters), and some envelope.
	maxMessage := int(*maxWrite)*6 + 64<<10
	if err := newServer(s, os.Stdout).serve(os.Stdin, maxMessage); err != nil {
		fmt.Fprintln(os.Stderr, serverName+":", err)
		os.Exit(1)
	}
}
