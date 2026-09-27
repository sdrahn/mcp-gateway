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
	n := a.hi - a.lo + 1
	total := n * (n - 1) / 2
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.inUse) >= total {
		return "", ErrMCSExhausted
	}
	for {
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
		k := [2]int{a.lo + x, a.lo + y}
		if !a.inUse[k] {
			a.inUse[k] = true
			return fmt.Sprintf("c%d,c%d", k[0], k[1]), nil
		}
	}
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
