package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/coreos/go-systemd/v22/daemon"
)

// statusInterval is how often the status line is renewed without a
// watchdog.
const statusInterval = 30 * time.Second

// sdNotify sends a state to systemd's notification socket (a no-op when
// the gateway does not run under systemd).
func sdNotify(state string) error {
	_, err := daemon.SdNotify(false, state)
	return err
}

// notifySystemd tells systemd that the gateway is ready (Type=notify),
// keeps its status line current and, when the unit has a watchdog
// (WatchdogSec=), pings it as long as probe answers in time. probe takes
// the locks of the router, the instance pool and the approval broker:
// when one of them is held forever, the pings stop and systemd restarts
// the gateway; with the default WatchdogSignal (SIGABRT) the Go runtime
// first writes every goroutine's stack to the journal. When ctx ends, it
// tells systemd that the gateway is stopping.
func notifySystemd(ctx context.Context, log *slog.Logger, notify func(string) error, watchdog time.Duration, probe func() string) {
	if err := notify(daemon.SdNotifyReady); err != nil {
		log.Warn("telling systemd that the gateway is ready failed", "err", err)
	}
	interval := statusInterval
	if watchdog > 0 {
		interval = watchdog / 3
		log.Info("systemd watchdog enabled", "timeout", watchdog)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	var running chan string // a probe that has not answered yet
	stuck := false
	for {
		if running == nil {
			running = make(chan string, 1)
			go func(c chan<- string) { c <- probe() }(running)
		}
		select {
		case status := <-running:
			running = nil
			if stuck {
				stuck = false
				log.Info("watchdog: the gateway responds again")
			}
			msg := "STATUS=" + status
			if watchdog > 0 {
				msg += "\n" + daemon.SdNotifyWatchdog
			}
			_ = notify(msg)
		case <-time.After(interval):
			if !stuck {
				stuck = true
				log.Error("watchdog: sessions, instances or approvals have been locked for too long; systemd is no longer told that the gateway is alive",
					"waited", interval)
			}
		case <-ctx.Done():
			_ = notify(daemon.SdNotifyStopping + "\nSTATUS=stopping: ending sessions, waiting for calls to privileged servers")
			return
		}
		select {
		case <-t.C:
		case <-ctx.Done():
			_ = notify(daemon.SdNotifyStopping + "\nSTATUS=stopping: ending sessions, waiting for calls to privileged servers")
			return
		}
	}
}

// statusLine describes the gateway for systemctl status.
func statusLine(sessions, instances, pending int) string {
	return fmt.Sprintf("%d sessions, %d server instances, %d pending approvals", sessions, instances, pending)
}
