package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
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
func (e *Exec) Start(_ context.Context, b *config.Backend, p principal.Principal, id string) (Instance, error) {
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
	credDir, err := stageCredentials(b)
	if err != nil {
		return nil, err
	}
	if credDir != "" {
		cmd.Env = append(cmd.Env, "CREDENTIALS_DIRECTORY="+credDir)
		if cred := cmd.SysProcAttr.Credential; cred != nil {
			if err := chownTree(credDir, int(cred.Uid), int(cred.Gid)); err != nil {
				removeCredentials(credDir)
				return nil, err
			}
		}
	}
	cleanup := func() {
		if credDir != "" {
			removeCredentials(credDir)
		}
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cleanup()
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cleanup()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cleanup()
		return nil, err
	}
	inst := &execInstance{name: unitName(b, id), cmd: cmd, stdin: stdin, stdout: stdout, done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		cleanup()
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

// stageCredentials copies the backend's credentials into a private
// directory, as systemd's LoadCredential= would (development mode only:
// here the gateway must be able to read them). It returns "" without
// credentials.
func stageCredentials(b *config.Backend) (string, error) {
	creds, err := b.ParseCredentials()
	if err != nil || len(creds) == 0 {
		return "", err
	}
	dir, err := os.MkdirTemp("", "mcp-credentials-")
	if err != nil {
		return "", err
	}
	for _, c := range creds {
		data, err := os.ReadFile(c.Path)
		if err != nil {
			_ = os.RemoveAll(dir)
			return "", fmt.Errorf("credential %s: %w", c.Name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, c.Name), data, 0o400); err != nil {
			_ = os.RemoveAll(dir)
			return "", err
		}
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return dir, nil
}

// removeCredentials deletes a staged credentials directory. It is
// read-only (0500), which would keep an unprivileged gateway from deleting
// the files in it, so make it writable first.
func removeCredentials(dir string) {
	_ = os.Chmod(dir, 0o700)
	_ = os.RemoveAll(dir)
}

func chownTree(dir string, uid, gid int) error {
	return filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(path, uid, gid)
	})
}
