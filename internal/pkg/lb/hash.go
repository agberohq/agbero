package lb

import (
	"sort"

	"github.com/cespare/xxhash/v2"
)

// Consistent for minimal redistribution using xxhash
type Consistent struct {
	ring     []uint64
	backends []int // maps ring position to backend index
	replicas int
}

// NewConsistent creates a consistent hash ring with xxhash
func NewConsistent(count int, replicas int) *Consistent {
	if count == 0 || replicas <= 0 {
		return &Consistent{}
	}

	r := &Consistent{
		ring:     make([]uint64, 0, count*replicas),
		backends: make([]int, 0, count*replicas),
		replicas: replicas,
	}

	// Use xxhash for better distribution
	for i := 0; i < count; i++ {
		for j := 0; j < replicas; j++ {
			// Create a unique key for each replica using xxhash
			key := make([]byte, 12)
			// Backend index
			key[0] = byte(i)
			key[1] = byte(i >> 8)
			key[2] = byte(i >> 16)
			key[3] = byte(i >> 24)
			// Replica index
			key[4] = byte(j)
			key[5] = byte(j >> 8)
			key[6] = byte(j >> 16)
			key[7] = byte(j >> 24)
			// Salt for better distribution
			key[8] = 0xde
			key[9] = 0xad
			key[10] = 0xbe
			key[11] = 0xef

			h := xxhash.Sum64(key)
			r.ring = append(r.ring, h)
			r.backends = append(r.backends, i)
		}
	}

	// Sort ring
	sort.Slice(r.ring, func(i, j int) bool {
		return r.ring[i] < r.ring[j]
	})

	return r
}

// Get returns backend index for key
func (r *Consistent) Get(key uint64) int {
	if len(r.ring) == 0 {
		return 0
	}

	idx := sort.Search(len(r.ring), func(i int) bool {
		return r.ring[i] >= key
	})

	if idx == len(r.ring) {
		idx = 0
	}

	return r.backends[idx]
}
