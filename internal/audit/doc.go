// Package audit emits structured audit records for every enforced message
// to journald, and security-relevant events additionally to the kernel
// audit subsystem, so they can be correlated with SELinux AVC records.
//
// See docs/architecture.md, section 5.9.
package audit
