package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// NVMe: the SMART / Health Information log (log page 0x02, NVM Express
// Base Specification 2.0, figure 207), read with Get Log Page through the
// admin passthrough ioctl on the namespace's block device. The kernel
// lets only CAP_SYS_ADMIN send Get Log Page (nvme_cmd_allowed).

const (
	nvmeIoctlAdminCmd = 0xC0484E41 // _IOWR('N', 0x41, struct nvme_passthru_cmd)
	nvmeAdminGetLog   = 0x02
	nvmeLogSMART      = 0x02
	nvmeLogSize       = 512
)

// nvmePassthru is struct nvme_passthru_cmd (linux/nvme_ioctl.h), 72 bytes.
type nvmePassthru struct {
	Opcode      uint8
	Flags       uint8
	Rsvd1       uint16
	NSID        uint32
	Cdw2, Cdw3  uint32
	Metadata    uint64
	Addr        uint64
	MetadataLen uint32
	DataLen     uint32
	Cdw10       uint32
	Cdw11       uint32
	Cdw12       uint32
	Cdw13       uint32
	Cdw14       uint32
	Cdw15       uint32
	TimeoutMs   uint32
	Result      uint32
}

// nvmeSMARTLog reads the controller's SMART / Health log through fd.
func nvmeSMARTLog(fd int) ([]byte, error) {
	buf := make([]byte, nvmeLogSize)
	cmd := nvmePassthru{
		Opcode:  nvmeAdminGetLog,
		NSID:    0xFFFFFFFF, // the controller as a whole
		Addr:    uint64(uintptr(unsafe.Pointer(&buf[0]))),
		DataLen: nvmeLogSize,
		// NUMDL (dwords - 1) in 31:16, the log page in 7:0.
		Cdw10:     uint32(nvmeLogSize/4-1)<<16 | nvmeLogSMART,
		TimeoutMs: 10000,
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), nvmeIoctlAdminCmd, uintptr(unsafe.Pointer(&cmd)))
	runtime.KeepAlive(buf)
	if errno != 0 {
		return nil, fmt.Errorf("NVMe Get Log Page: %w", errno)
	}
	if cmd.Result != 0 {
		return nil, fmt.Errorf("NVMe Get Log Page: status 0x%x", cmd.Result)
	}
	return buf, nil
}

// NVMeHealth is the SMART / Health log, decoded.
type NVMeHealth struct {
	CriticalWarning     uint8    `json:"critical_warning"`
	CriticalWarnings    []string `json:"critical_warnings"`
	TemperatureCelsius  int      `json:"temperature_celsius"`
	AvailableSpare      uint8    `json:"available_spare_percent"`
	SpareThreshold      uint8    `json:"available_spare_threshold_percent"`
	PercentageUsed      uint8    `json:"percentage_used"`
	DataUnitsRead       uint64   `json:"data_units_read"`
	DataUnitsWritten    uint64   `json:"data_units_written"`
	PowerCycles         uint64   `json:"power_cycles"`
	PowerOnHours        uint64   `json:"power_on_hours"`
	UnsafeShutdowns     uint64   `json:"unsafe_shutdowns"`
	MediaErrors         uint64   `json:"media_and_data_integrity_errors"`
	ErrorLogEntries     uint64   `json:"error_log_entries"`
	WarningTempMinutes  uint32   `json:"warning_temperature_minutes"`
	CriticalTempMinutes uint32   `json:"critical_temperature_minutes"`
}

// criticalWarningBits are the critical warning's bits (figure 207).
var criticalWarningBits = []string{
	"available spare below threshold",
	"temperature outside its thresholds",
	"reliability degraded by media or internal errors",
	"media placed in read-only mode",
	"volatile memory backup device failed",
	"persistent memory region read-only or unreliable",
}

// u128lo is the low 64 bits of a little-endian 128-bit counter.
func u128lo(b []byte) uint64 { return binary.LittleEndian.Uint64(b[:8]) }

func parseNVMeSMART(b []byte) (NVMeHealth, error) {
	if len(b) < nvmeLogSize {
		return NVMeHealth{}, errors.New("NVMe SMART log: short")
	}
	h := NVMeHealth{
		CriticalWarning:     b[0],
		CriticalWarnings:    []string{},
		TemperatureCelsius:  int(binary.LittleEndian.Uint16(b[1:3])) - 273,
		AvailableSpare:      b[3],
		SpareThreshold:      b[4],
		PercentageUsed:      b[5],
		DataUnitsRead:       u128lo(b[32:]),
		DataUnitsWritten:    u128lo(b[48:]),
		PowerCycles:         u128lo(b[112:]),
		PowerOnHours:        u128lo(b[128:]),
		UnsafeShutdowns:     u128lo(b[144:]),
		MediaErrors:         u128lo(b[160:]),
		ErrorLogEntries:     u128lo(b[176:]),
		WarningTempMinutes:  binary.LittleEndian.Uint32(b[192:]),
		CriticalTempMinutes: binary.LittleEndian.Uint32(b[196:]),
	}
	for i, name := range criticalWarningBits {
		if h.CriticalWarning&(1<<i) != 0 {
			h.CriticalWarnings = append(h.CriticalWarnings, name)
		}
	}
	return h, nil
}

// NVMe verdict thresholds.
const (
	nvmeUsedWarning = 90 // percentage used, of the rated endurance
)

// verdict judges an NVMe health log: failing when the controller says
// reliability is degraded, the media is read-only or the spare is below
// its threshold; warning on any other critical warning, media errors or
// wear from nvmeUsedWarning percent.
func (h NVMeHealth) verdict() (string, []string) {
	var failing, warning []string
	for i, name := range criticalWarningBits {
		if h.CriticalWarning&(1<<i) == 0 {
			continue
		}
		if i == 0 || i == 2 || i == 3 {
			failing = append(failing, name)
		} else {
			warning = append(warning, name)
		}
	}
	if h.SpareThreshold > 0 && h.AvailableSpare < h.SpareThreshold && h.CriticalWarning&1 == 0 {
		failing = append(failing, fmt.Sprintf("available spare %d%% below its threshold %d%%", h.AvailableSpare, h.SpareThreshold))
	}
	if h.MediaErrors > 0 {
		warning = append(warning, fmt.Sprintf("%d media and data integrity errors", h.MediaErrors))
	}
	if h.PercentageUsed >= nvmeUsedWarning {
		warning = append(warning, fmt.Sprintf("%d%% of the rated endurance used", h.PercentageUsed))
	}
	return judge(failing, warning)
}

// judge: failing if any reason fails, warning if any warns, else ok.
func judge(failing, warning []string) (string, []string) {
	switch {
	case len(failing) > 0:
		return "failing", append(failing, warning...)
	case len(warning) > 0:
		return "warning", warning
	}
	return "ok", []string{}
}
