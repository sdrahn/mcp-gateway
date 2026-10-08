package supervisor

import (
	"fmt"
	"log/slog"

	"github.com/sdrahn/mcp-gateway/internal/config"
)

// NewLauncher returns the launcher for the configured supervisor mode.
func NewLauncher(log *slog.Logger, s config.Supervisor) (Launcher, error) {
	switch s.Mode {
	case "exec":
		log.Warn("supervisor mode exec: backends run as child processes without systemd's sandbox and SELinux, under their landlock only (development only)")
		return &Exec{Log: log}, nil
	case "systemd":
		useSELinux := s.SELinux == "on" || (s.SELinux == "auto" && SELinuxEnabled())
		lo, hi, err := s.MCSCategories()
		if err != nil {
			return nil, err
		}
		mcs := NewMCSAllocator(lo, hi)
		if s.MCSAvoid == "auto" {
			// Skip pairs of running containers and virtual machines.
			mcs.Foreign = func() map[[2]int]ForeignProc { return ScanMCS("/proc").Pairs }
		}
		log.Info("supervisor mode systemd", "selinux", useSELinux, "mcs_range", s.MCSRange, "mcs_avoid", s.MCSAvoid)
		return &Systemd{Log: log, SELinux: useSELinux, MCS: mcs}, nil
	}
	return nil, fmt.Errorf("unknown supervisor mode %q", s.Mode)
}
