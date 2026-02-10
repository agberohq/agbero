package lb

import (
	"math"
	"math/rand/v2"
	"sync"
)

var rngPool = sync.Pool{
	New: func() any {
		// Each goroutine gets its own seeded generator
		return rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	},
}

type rng struct {
	s [4]uint64
}

func newRng(seed uint64) *rng {
	var r rng
	r.s[0] = seed
	r.s[1] = seed*0x9e3779b97f4a7c15 + 0xbf58476d1ce4e5b9
	r.s[2] = seed ^ 0x94d049bb133111eb
	r.s[3] = seed + 0x2545f4914f6cdd1d
	return &r
}

func (r *rng) Uint64() uint64 {
	x := r.s[0]
	y := r.s[3]
	result := x + y
	y ^= x
	r.s[0] = r.rotl(x, 24) ^ y ^ (y << 16)
	r.s[3] = r.rotl(y, 37)
	return result
}

func (r *rng) Uint64n(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	mask := n - 1
	if (n & mask) == 0 {
		return r.Uint64() & mask
	}
	limit := math.MaxUint64 - (math.MaxUint64 % n)
	for {
		v := r.Uint64()
		if v < limit {
			return v % n
		}
	}
}

func (r *rng) rotl(x uint64, k int) uint64 { return (x << k) | (x >> (64 - k)) }
