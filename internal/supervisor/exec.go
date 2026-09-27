package supervisor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/sdrahn/mcp-gateway/internal/config"
	"github.com/sdrahn/mcp-gateway/internal/principal"
)

// Exec starts backends as plain child processes of the gateway. There is
// no sandbox and no SELinux domain transition beyond what the binary's
// label implies: development only. When the gateway runs as root and the
// backend runs as the principal, the child's credentials are switched.
type Exec struct {
	Log *slog.Logger
}

type execInstance struct {
	name   string
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	done   chan struct{}
}

// Start implements Launcher.
func (e *Exec) Start(_ context.Context, b *config.Backend, p principal.Principal) (Instance, error) {
	argv := command(b, p)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = environment(b, p)
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	if os.Geteuid() == 0 && b.RunAs == "principal" && p.UID != nil && *p.UID != 0 {
		u, err := user.LookupId(strconv.FormatUint(uint64(*p.UID), 10))
		if err != nil {
			return nil, err
		}
		gid, err := strconv.ParseUint(u.Gid, 10, 32)
		if err != nil {
			return nil, err
		}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: *p.UID, Gid: uint32(gid)}
	}
	if p.Home != "" {
		cmd.Dir = p.Home
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	inst := &execInstance{name: unitName(b, p), cmd: cmd, stdin: stdin, stdout: stdout, done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		if e.Log != nil {
			e.Log.Info("backend exited", "instance", inst.name, "err", err)
		}
		close(inst.done)
	}()
	return inst, nil
}

func (i *execInstance) Read(p []byte) (int, error)  { return i.stdout.Read(p) }
func (i *execInstance) Write(p []byte) (int, error) { return i.stdin.Write(p) }
func (i *execInstance) Name() string                { return i.name }

// Close closes stdin, which ends a well-behaved stdio server, and kills
// the process group if it has not exited within two seconds.
func (i *execInstance) Close() error {
	err := i.stdin.Close()
	select {
	case <-i.done:
	case <-time.After(2 * time.Second):
		_ = syscall.Kill(-i.cmd.Process.Pid, syscall.SIGKILL)
		<-i.done
	}
	if errors.Is(err, os.ErrClosed) {
		err = nil
	}
	return err
}
