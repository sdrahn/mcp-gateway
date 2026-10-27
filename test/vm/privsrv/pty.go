package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// runPTY runs argv in a terminal of its own (a pty, its controlling
// terminal), as a user at a terminal would, and types password at the
// first "Password:" prompt (polkit's text agent asks for it, roadmap
// step 40); an empty password answers nothing. A second prompt (a wrong
// password) ends the command. It copies the terminal's output to stdout
// and exits as the command does.
func runPTY(password string, argv []string) error {
	master, slavePath, err := openPTY()
	if err != nil {
		return err
	}
	defer func() { _ = master.Close() }()
	slave, err := os.OpenFile(slavePath, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return err
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		_ = slave.Close()
		return err
	}
	_ = slave.Close()
	var out bytes.Buffer
	prompts := 0
	buf := make([]byte, 4096)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for {
		n, err := master.Read(buf)
		if n > 0 {
			_, _ = os.Stdout.Write(buf[:n])
			out.Write(buf[:n])
			if c := bytes.Count(out.Bytes(), []byte("Password:")); c > prompts {
				prompts = c
				if prompts > 1 || password == "" {
					_ = cmd.Process.Kill()
				} else {
					time.Sleep(200 * time.Millisecond) // the agent turns echo off first
					_, _ = io.WriteString(master, password+"\n")
				}
			}
		}
		if err != nil {
			break // EIO: the command closed the terminal
		}
	}
	err = <-done
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		os.Exit(exit.ExitCode())
	}
	return err
}

// openPTY opens a pseudo-terminal pair's master and names its slave.
func openPTY() (*os.File, string, error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", fmt.Errorf("pty: %w", err)
	}
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("pty: unlock: %w", err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("pty: %w", err)
	}
	return os.NewFile(uintptr(fd), "/dev/ptmx"), "/dev/pts/" + strconv.Itoa(n), nil
}
