package kube

import (
	"net/url"
	"time"
)

// LeasesPath is the path of the Leases (coordination.k8s.io/v1) in ns.
func LeasesPath(ns string) string {
	return "/apis/coordination.k8s.io/v1/namespaces/" + url.PathEscape(ns) + "/leases"
}

// Lease is a coordination.k8s.io/v1 Lease.
type Lease struct {
	APIVersion string     `json:"apiVersion"`
	Kind       string     `json:"kind"`
	Metadata   ObjectMeta `json:"metadata"`
	Spec       LeaseSpec  `json:"spec"`
}

// LeaseSpec is who holds a Lease, for how long, since when.
type LeaseSpec struct {
	HolderIdentity       string     `json:"holderIdentity,omitempty"`
	LeaseDurationSeconds int        `json:"leaseDurationSeconds,omitempty"`
	AcquireTime          *MicroTime `json:"acquireTime,omitempty"`
	RenewTime            *MicroTime `json:"renewTime,omitempty"`
	LeaseTransitions     int        `json:"leaseTransitions,omitempty"`
}

// Expires is when the Lease runs out unless it is renewed (the zero time
// for one never renewed).
func (s LeaseSpec) Expires() time.Time {
	if s.RenewTime == nil {
		return time.Time{}
	}
	return s.RenewTime.Add(time.Duration(s.LeaseDurationSeconds) * time.Second)
}

// LeaseList is a coordination.k8s.io/v1 LeaseList.
type LeaseList struct {
	Metadata ListMeta `json:"metadata"`
	Items    []Lease  `json:"items"`
}

// MicroTime is a time with microseconds, as the API writes Leases' times.
type MicroTime struct{ time.Time }

const microTimeLayout = "2006-01-02T15:04:05.000000Z07:00"

// NewMicroTime returns t as a MicroTime, in UTC.
func NewMicroTime(t time.Time) *MicroTime { return &MicroTime{t.UTC()} }

func (t MicroTime) MarshalJSON() ([]byte, error) {
	return []byte(`"` + t.UTC().Format(microTimeLayout) + `"`), nil
}

func (t *MicroTime) UnmarshalJSON(b []byte) error {
	s := string(b)
	if s == "null" {
		return nil
	}
	if len(s) < 2 {
		return &time.ParseError{Value: s}
	}
	v, err := time.Parse(time.RFC3339Nano, s[1:len(s)-1])
	if err != nil {
		return err
	}
	t.Time = v
	return nil
}
