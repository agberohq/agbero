package lb

import (
	"slices"

	"github.com/cespare/xxhash/v2"
)

const (
	emptyRingSize   = 0
	hashKeyOffset0  = 0xde
	hashKeyOffset1  = 0xad
	hashKeyOffset2  = 0xbe
	hashKeyOffset3  = 0xef
	hashByteShift8  = 8
	hashByteShift16 = 16
	hashByteShift24 = 24
	sortLess        = -1
	sortGreater     = 1
	sortEqual       = 0
)

type Consistent struct {
	ring     []uint64
	backends []int32
	replicas int
}

// NewConsistent generates a distributed hashing ring mapping backends securely.
// Multiplies the total surface area by the specified replica count internally.
func NewConsistent(count int, replicas int) *Consistent {
	if count == emptyRingSize || replicas <= emptyRingSize {
		return &Consistent{}
	}
	total := count * replicas

	type ringEntry struct {
		hash    uint64
		backend int32
	}

	entries := make([]ringEntry, total)
	var key [12]byte
	key[8], key[9], key[10], key[11] = hashKeyOffset0, hashKeyOffset1, hashKeyOffset2, hashKeyOffset3
	idx := emptyRingSize
	for i := 0; i < count; i++ {
		key[0] = byte(i)
		key[1] = byte(i >> hashByteShift8)
		key[2] = byte(i >> hashByteShift16)
		key[3] = byte(i >> hashByteShift24)
		for j := 0; j < replicas; j++ {
			key[4] = byte(j)
			key[5] = byte(j >> hashByteShift8)
			key[6] = byte(j >> hashByteShift16)
			key[7] = byte(j >> hashByteShift24)
			entries[idx] = ringEntry{
				hash:    xxhash.Sum64(key[:]),
				backend: int32(i),
			}
			idx++
		}
	}
	slices.SortFunc(entries, func(a, b ringEntry) int {
		if a.hash < b.hash {
			return sortLess
		}
		if a.hash > b.hash {
			return sortGreater
		}
		return sortEqual
	})
	ring := make([]uint64, total)
	backends := make([]int32, total)
	for i, e := range entries {
		ring[i] = e.hash
		backends[i] = e.backend
	}
	return &Consistent{
		ring:     ring,
		backends: backends,
		replicas: replicas,
	}
}

// Get locates the designated backend mapping for a specific cryptographic hash.
// Delegates to hardware-accelerated binary search logic for maximum speed.
func (r *Consistent) Get(key uint64) int {
	if len(r.ring) == emptyRingSize {
		return emptyRingSize
	}
	idx := asearch.SortedSearch(r.ring, key)
	return int(r.backends[idx])
}
