// Package fswatch tells when something changes in a set of directories,
// with inotify. It reports only that something changed, not what: the
// caller compares what it cares about (the gateway digests its files)
// and keeps polling as the fallback for directories it cannot watch.
package fswatch

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"

	"golang.org/x/sys/unix"
)

// mask covers a file written and closed, created, removed, renamed into
// or out of the directory (an editor's or certbot's replace), its
// metadata changed (a chmod making it readable), and the directory itself
// removed or moved.
const mask = unix.IN_CLOSE_WRITE | unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_TO |
	unix.IN_MOVED_FROM | unix.IN_ATTRIB | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF

// Watcher watches directories. Events gets a value (coalesced, never
// blocking the reader) whenever something in one of them changes.
type Watcher struct {
	f      *os.File // reads the events; Fd would make it blocking
	fd     int      // the same descriptor, for adding and removing watches
	events chan struct{}

	mu      sync.Mutex
	closed  bool
	watches map[string]int // directory to watch descriptor
}

// New starts a watcher with no directories.
func New() (*Watcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify: %w", err)
	}
	w := &Watcher{f: os.NewFile(uintptr(fd), "inotify"), fd: fd, events: make(chan struct{}, 1), watches: map[string]int{}}
	go w.read()
	return w, nil
}

// Events delivers a value after a change; several changes before it is
// read count as one.
func (w *Watcher) Events() <-chan struct{} {
	if w == nil {
		return nil
	}
	return w.events
}

// Set watches exactly dirs: new ones are added, ones not listed are
// dropped, and a directory removed and created again is watched anew.
// It returns, per directory, why it cannot be watched (it does not
// exist, inotify's limit is reached, SELinux denies it); changes there go
// unnoticed until a later Set succeeds.
func (w *Watcher) Set(dirs []string) map[string]error {
	w.mu.Lock()
	defer w.mu.Unlock()
	failed := map[string]error{}
	if w.closed {
		for _, dir := range dirs {
			failed[dir] = os.ErrClosed
		}
		return failed
	}
	for dir, wd := range w.watches {
		if !slices.Contains(dirs, dir) {
			_, _ = unix.InotifyRmWatch(w.fd, uint32(wd))
			delete(w.watches, dir)
		}
	}
	for _, dir := range dirs {
		// Added again even if watched: inotify returns the same
		// descriptor for the same directory, and a new one for a
		// directory that replaced it.
		wd, err := unix.InotifyAddWatch(w.fd, dir, mask|unix.IN_ONLYDIR)
		if err != nil {
			delete(w.watches, dir)
			failed[dir] = err
			continue
		}
		w.watches[dir] = wd
	}
	return failed
}

// Close stops the watcher.
func (w *Watcher) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return w.f.Close()
}

func (w *Watcher) read() {
	buf := make([]byte, 64*(unix.SizeofInotifyEvent+unix.PathMax))
	for {
		n, err := w.f.Read(buf)
		if n > 0 {
			// Any event, including a queue overflow, means "look".
			select {
			case w.events <- struct{}{}:
			default:
			}
		}
		if err != nil && !errors.Is(err, unix.EINTR) {
			return // closed
		}
	}
}
