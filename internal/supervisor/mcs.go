package supervisor

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync"
)

// MCSAllocator hands out unique category pairs "cA,cB" (A < B), as sVirt
// does for virtual machines, so instances running as the same Unix user
// still cannot access each other.
type MCSAllocator struct {
	lo, hi int // inclusive category range

	// Foreign, if set, reports pairs held by other workloads (containers,
	// virtual machines), which are skipped.
	Foreign func() map[[2]int]ForeignProc

	mu    sync.Mutex
	inUse map[[2]int]bool
}

// NewMCSAllocator allocates from categories lo..hi (inclusive).
func NewMCSAllocator(lo, hi int) *MCSAllocator {
	return &MCSAllocator{lo: lo, hi: hi, inUse: map[[2]int]bool{}}
}

// ErrMCSExhausted means every pair in the range is in use.
var ErrMCSExhausted = errors.New("supervisor: MCS category pairs exhausted")

// Allocate returns a free pair, e.g. "c12,c40".
func (a *MCSAllocator) Allocate() (string, error) {
	var foreign map[[2]int]ForeignProc
	if a.Foreign != nil {
		foreign = a.Foreign()
	}
	n := a.hi - a.lo + 1
	total := n * (n - 1) / 2
	a.mu.Lock()
	defer a.mu.Unlock()
	taken := func(k [2]int) bool {
		_, f := foreign[k]
		return a.inUse[k] || f
	}
	used := len(a.inUse)
	for k := range foreign {
		if k[0] >= a.lo && k[1] <= a.hi && !a.inUse[k] {
			used++
		}
	}
	if used >= total {
		return "", ErrMCSExhausted
	}
	take := func(k [2]int) string {
		a.inUse[k] = true
		return fmt.Sprintf("c%d,c%d", k[0], k[1])
	}
	// Random pairs, like sVirt; when the range is nearly full, the first
	// free one.
	for range 1000 {
		x, err := randInt(n)
		if err != nil {
			return "", err
		}
		y, err := randInt(n)
		if err != nil {
			return "", err
		}
		if x == y {
			continue
		}
		if x > y {
			x, y = y, x
		}
		if k := [2]int{a.lo + x, a.lo + y}; !taken(k) {
			return take(k), nil
		}
	}
	for x := a.lo; x <= a.hi; x++ {
		for y := x + 1; y <= a.hi; y++ {
			if k := [2]int{x, y}; !taken(k) {
				return take(k), nil
			}
		}
	}
	return "", ErrMCSExhausted
}

// Release frees a pair returned by Allocate.
func (a *MCSAllocator) Release(pair string) {
	var x, y int
	if _, err := fmt.Sscanf(pair, "c%d,c%d", &x, &y); err != nil {
		return
	}
	a.mu.Lock()
	delete(a.inUse, [2]int{x, y})
	a.mu.Unlock()
}

func randInt(n int) (int, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(v.Int64()), nil
}
