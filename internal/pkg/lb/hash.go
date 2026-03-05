package lb

import (
	"slices"

	"github.com/cespare/xxhash/v2"
)

type ringEntry struct {
	hash    uint64
	backend int
}

type Consistent struct {
	ring     []uint64
	backends []int
	replicas int
}

func NewConsistent(count int, replicas int) *Consistent {
	if count == 0 || replicas <= 0 {
		return &Consistent{}
	}

	total := count * replicas
	entries := make([]ringEntry, total)

	var key [12]byte
	key[8], key[9], key[10], key[11] = 0xde, 0xad, 0xbe, 0xef

	idx := 0
	for i := range count {
		key[0] = byte(i)
		key[1] = byte(i >> 8)
		key[2] = byte(i >> 16)
		key[3] = byte(i >> 24)

		for j := range replicas {
			key[4] = byte(j)
			key[5] = byte(j >> 8)
			key[6] = byte(j >> 16)
			key[7] = byte(j >> 24)

			entries[idx] = ringEntry{
				hash:    xxhash.Sum64(key[:]),
				backend: i,
			}
			idx++
		}
	}

	slices.SortFunc(entries, func(a, b ringEntry) int {
		if a.hash < b.hash {
			return -1
		}
		if a.hash > b.hash {
			return 1
		}
		return 0
	})

	r := &Consistent{
		ring:     make([]uint64, total),
		backends: make([]int, total),
		replicas: replicas,
	}

	for i, e := range entries {
		r.ring[i] = e.hash
		r.backends[i] = e.backend
	}

	return r
}

func (r *Consistent) Get(key uint64) int {
	if len(r.ring) == 0 {
		return 0
	}

	idx, _ := slices.BinarySearch(r.ring, key)
	if idx == len(r.ring) {
		idx = 0
	}

	return r.backends[idx]
}
