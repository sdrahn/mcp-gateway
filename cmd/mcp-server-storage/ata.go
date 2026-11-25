package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// SATA: SMART through ATA PASS-THROUGH(16) (SAT, T10/BSR INCITS 491) over
// SG_IO on the disk's block device: RETURN STATUS (the drive's own pass
// or fail), READ DATA (the attribute table) and READ THRESHOLDS. The
// kernel lets only CAP_SYS_RAWIO send ATA PASS-THROUGH (scsi_cmd_allowed).

const (
	sgIO           = 0x2285
	sgDxferNone    = -1
	sgDxferFromDev = -3
	ataPassThru16  = 0x85
	ataSMART       = 0xB0
	smartReadData  = 0xD0
	smartReadThres = 0xD1
	smartStatus    = 0xDA
	smartLBAMid    = 0x4F
	smartLBAHigh   = 0xC2
)

// sgIOHdr is struct sg_io_hdr (scsi/sg.h), 88 bytes on 64-bit.
type sgIOHdr struct {
	InterfaceID    int32
	DxferDirection int32
	CmdLen         uint8
	MxSbLen        uint8
	IovecCount     uint16
	DxferLen       uint32
	Dxferp         uintptr
	Cmdp           uintptr
	Sbp            uintptr
	Timeout        uint32
	Flags          uint32
	PackID         int32
	_              int32
	UsrPtr         uintptr
	Status         uint8
	MaskedStatus   uint8
	MsgStatus      uint8
	SbLenWr        uint8
	HostStatus     uint16
	DriverStatus   uint16
	Resid          int32
	Duration       uint32
	Info           uint32
	_              uint32
}

// smartCDB is an ATA PASS-THROUGH(16) of SMART with feature: PIO data-in
// of one sector, or with data false non-data asking for the result
// registers (CK_COND).
func smartCDB(feature byte, data bool) []byte {
	cdb := make([]byte, 16)
	cdb[0] = ataPassThru16
	if data {
		cdb[1] = 4 << 1 // protocol: PIO data-in
		cdb[2] = 0x0e   // T_DIR from device, BYT_BLOK, T_LENGTH in the sector count
		cdb[6] = 1      // one sector
	} else {
		cdb[1] = 3 << 1 // protocol: non-data
		cdb[2] = 0x20   // CK_COND: return the registers in the sense data
	}
	cdb[4] = feature
	cdb[10] = smartLBAMid
	cdb[12] = smartLBAHigh
	cdb[14] = ataSMART
	return cdb
}

// sgCommand sends cdb through SG_IO; data, if any, is read from the
// device. It returns the sense data.
func sgCommand(fd int, cdb, data []byte) ([]byte, uint8, error) {
	sense := make([]byte, 32)
	h := sgIOHdr{InterfaceID: 'S', DxferDirection: sgDxferNone, CmdLen: uint8(len(cdb)), MxSbLen: uint8(len(sense)),
		Cmdp: uintptr(unsafe.Pointer(&cdb[0])), Sbp: uintptr(unsafe.Pointer(&sense[0])), Timeout: 10000}
	if len(data) > 0 {
		h.DxferDirection, h.DxferLen, h.Dxferp = sgDxferFromDev, uint32(len(data)), uintptr(unsafe.Pointer(&data[0]))
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), sgIO, uintptr(unsafe.Pointer(&h)))
	runtime.KeepAlive(cdb)
	runtime.KeepAlive(data)
	runtime.KeepAlive(sense)
	if errno != 0 {
		return nil, 0, fmt.Errorf("SG_IO: %w", errno)
	}
	if h.HostStatus != 0 || h.DriverStatus&0x0f != 0 && h.DriverStatus&0x0f != 0x08 { // 0x08: DRIVER_SENSE
		return nil, 0, fmt.Errorf("SG_IO: host status 0x%x, driver status 0x%x", h.HostStatus, h.DriverStatus)
	}
	return sense[:h.SbLenWr], h.Status, nil
}

// ataSMART reads a SATA disk's SMART through fd: the drive's status
// (RETURN STATUS), the attribute values and their thresholds.
func ataSMARTRead(fd int) (status []byte, values, thresholds []byte, err error) {
	sense, _, err := sgCommand(fd, smartCDB(smartStatus, false), nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("SMART RETURN STATUS: %w", err)
	}
	values = make([]byte, 512)
	if sense2, st, err := sgCommand(fd, smartCDB(smartReadData, true), values); err != nil {
		return nil, nil, nil, fmt.Errorf("SMART READ DATA: %w", err)
	} else if st != 0 {
		return nil, nil, nil, fmt.Errorf("SMART READ DATA: SCSI status 0x%x (sense % x): SMART may be disabled", st, sense2)
	}
	thresholds = make([]byte, 512)
	if _, st, err := sgCommand(fd, smartCDB(smartReadThres, true), thresholds); err != nil || st != 0 {
		thresholds = nil // obsolete in ACS: without it, no attribute is judged by its threshold
	}
	return sense, values, thresholds, nil
}

// smartStatusOK reads RETURN STATUS's result from the sense data: LBA
// mid and high 4Fh C2h mean the drive found no threshold exceeded, F4h 2Ch
// that it did. The registers are in the ATA Status Return descriptor
// (descriptor format) or, in fixed format, the information and
// command-specific fields (libata's ata_gen_passthru_sense).
func smartStatusOK(sense []byte) (ok bool, err error) {
	var mid, high byte
	switch {
	case len(sense) >= 8 && sense[0]&0x7f == 0x72:
		found := false
		for d := sense[8:]; len(d) >= 2; {
			n := int(d[1]) + 2
			if n > len(d) {
				break
			}
			if d[0] == 0x09 && n >= 14 {
				mid, high, found = d[9], d[11], true
				break
			}
			d = d[n:]
		}
		if !found {
			return false, errors.New("SMART RETURN STATUS: no ATA status in the sense data")
		}
	case len(sense) >= 14 && sense[0]&0x7f == 0x70:
		mid, high = sense[12], sense[13]
	default:
		return false, fmt.Errorf("SMART RETURN STATUS: unexpected sense data % x", sense)
	}
	switch {
	case mid == 0x4F && high == 0xC2:
		return true, nil
	case mid == 0xF4 && high == 0x2C:
		return false, nil
	}
	return false, fmt.Errorf("SMART RETURN STATUS: unexpected registers %02x %02x", mid, high)
}

// ATAAttribute is one SMART attribute.
type ATAAttribute struct {
	ID         uint8  `json:"id"`
	Name       string `json:"name"`
	Value      uint8  `json:"value"`
	Worst      uint8  `json:"worst"`
	Threshold  uint8  `json:"threshold"`
	Raw        uint64 `json:"raw"`
	PreFailure bool   `json:"pre_failure"`
	// Failing: the normalized value is at or below its threshold.
	Failing bool `json:"failing"`
}

// ATAHealth is a SATA disk's SMART.
type ATAHealth struct {
	// StatusPassed is the drive's own verdict (RETURN STATUS).
	StatusPassed       bool           `json:"smart_status_passed"`
	TemperatureCelsius *int           `json:"temperature_celsius,omitempty"`
	PowerOnHours       *uint64        `json:"power_on_hours,omitempty"`
	Attributes         []ATAAttribute `json:"attributes"`
}

// ataAttributeNames are the commonly agreed meanings; vendors differ for
// the rest.
var ataAttributeNames = map[uint8]string{
	1: "Raw_Read_Error_Rate", 5: "Reallocated_Sector_Ct", 9: "Power_On_Hours", 10: "Spin_Retry_Count",
	12: "Power_Cycle_Count", 171: "Program_Fail_Count", 172: "Erase_Fail_Count", 173: "Wear_Leveling_Count",
	174: "Unexpect_Power_Loss_Ct", 177: "Wear_Leveling_Count", 179: "Used_Rsvd_Blk_Cnt_Tot", 181: "Program_Fail_Cnt_Total",
	182: "Erase_Fail_Count_Total", 183: "Runtime_Bad_Block", 184: "End-to-End_Error", 187: "Reported_Uncorrect",
	188: "Command_Timeout", 190: "Airflow_Temperature_Cel", 192: "Power-Off_Retract_Count", 194: "Temperature_Celsius",
	195: "Hardware_ECC_Recovered", 196: "Reallocated_Event_Count", 197: "Current_Pending_Sector",
	198: "Offline_Uncorrectable", 199: "UDMA_CRC_Error_Count", 231: "SSD_Life_Left", 232: "Available_Reservd_Space",
	233: "Media_Wearout_Indicator", 241: "Total_LBAs_Written", 242: "Total_LBAs_Read",
}

// parseATASMART decodes the attribute table (30 entries of 12 bytes from
// byte 2) and its thresholds (same layout).
func parseATASMART(statusPassed bool, values, thresholds []byte) (ATAHealth, error) {
	if len(values) < 362 {
		return ATAHealth{}, errors.New("SMART data: short")
	}
	h := ATAHealth{StatusPassed: statusPassed, Attributes: []ATAAttribute{}}
	thr := map[uint8]uint8{}
	if len(thresholds) >= 362 {
		for i := 0; i < 30; i++ {
			e := thresholds[2+12*i:]
			if e[0] != 0 {
				thr[e[0]] = e[1]
			}
		}
	}
	for i := 0; i < 30; i++ {
		e := values[2+12*i:]
		if e[0] == 0 {
			continue
		}
		raw := uint64(0)
		for j := 5; j >= 0; j-- {
			raw = raw<<8 | uint64(e[5+j])
		}
		a := ATAAttribute{ID: e[0], Name: ataAttributeNames[e[0]], Value: e[3], Worst: e[4], Threshold: thr[e[0]], Raw: raw,
			PreFailure: binary.LittleEndian.Uint16(e[1:3])&1 != 0}
		if a.Name == "" {
			a.Name = fmt.Sprintf("Unknown_Attribute_%d", a.ID)
		}
		// A threshold of 0 never trips; 0xFE and above are "always
		// passing" by convention.
		a.Failing = a.Threshold > 0 && a.Threshold < 0xFE && a.Value <= a.Threshold
		switch a.ID {
		case 194, 190:
			if h.TemperatureCelsius == nil {
				t := int(raw & 0xff)
				h.TemperatureCelsius = &t
			}
		case 9:
			poh := raw & 0xffffffff
			h.PowerOnHours = &poh
		}
		h.Attributes = append(h.Attributes, a)
	}
	return h, nil
}

// ataWarnIfRaw are the attributes whose raw count above 0 is a warning:
// sectors reallocated, pending or uncorrectable, errors reported.
var ataWarnIfRaw = []uint8{5, 187, 197, 198}

// verdict judges a SATA disk's SMART: failing when the drive says so
// (RETURN STATUS) or a pre-failure attribute is at its threshold;
// warning when another attribute is, or when sectors were reallocated,
// are pending or uncorrectable, or errors were reported.
func (h ATAHealth) verdict() (string, []string) {
	var failing, warning []string
	if !h.StatusPassed {
		failing = append(failing, "the drive reports a SMART threshold exceeded (RETURN STATUS)")
	}
	for _, a := range h.Attributes {
		if a.Failing {
			msg := fmt.Sprintf("attribute %d %s at %d, threshold %d", a.ID, a.Name, a.Value, a.Threshold)
			if a.PreFailure {
				failing = append(failing, msg)
			} else {
				warning = append(warning, msg)
			}
		}
		for _, id := range ataWarnIfRaw {
			if a.ID == id && a.Raw > 0 {
				warning = append(warning, fmt.Sprintf("attribute %d %s raw %d", a.ID, a.Name, a.Raw))
			}
		}
	}
	return judge(failing, warning)
}
