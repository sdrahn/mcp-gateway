package main

import (
	"io"
	"os"
	"os/exec"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// ttyAgentWait bounds the wait for pkttyagent to register.
const ttyAgentWait = 5 * time.Second

// startTTYAgent runs polkit's text agent for this process when standard
// input is a terminal, as systemctl does, so that polkit can ask for the
// user's password in it when the gateway checks an approval of the
// user's own request (roadmap step 40). It returns once the agent is
// registered (or failed to), and a function that stops it. Without a
// terminal, or without pkttyagent, there is no one to ask: the gateway
// then refuses the approval and says so.
func startTTYAgent() (stop func()) {
	if _, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS); err != nil {
		return func() {}
	}
	path, err := exec.LookPath("pkttyagent")
	if err != nil {
		return func() {}
	}
	r, w, err := os.Pipe()
	if err != nil {
		return func() {}
	}
	defer func() { _ = r.Close() }()
	cmd := exec.Command(path, "--process", strconv.Itoa(os.Getpid()), "--notify-fd", "3", "--fallback")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	cmd.ExtraFiles = []*os.File{w}
	err = cmd.Start()
	_ = w.Close()
	if err != nil {
		return func() {}
	}
	// pkttyagent closes the notify fd once it is registered.
	registered := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, r); close(registered) }()
	select {
	case <-registered:
	case <-time.After(ttyAgentWait):
	}
	return func() {
		_ = cmd.Process.Signal(unix.SIGTERM)
		_ = cmd.Wait()
	}
}
