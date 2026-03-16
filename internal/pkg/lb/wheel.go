package lb

import (
	"math/rand/v2"
)

const (
	emptyValue = 0
	unitWeight = 1
)

type WeightWheel struct {
	cumul []uint64
	total uint64
}

// NewWheel constructs a distributed scale mapped directly to backend capacities
// Normalizes empty variables guarding against zero-sum divisions implicitly
func NewWheel(weights []int) *WeightWheel {
	if len(weights) == 0 {
		return &WeightWheel{}
	}

	cumul := make([]uint64, len(weights))
	var sum uint64
	allOne := true

	for i, w := range weights {
		if w <= emptyValue {
			w = unitWeight
		}
		if w != unitWeight {
			allOne = false
		}
		sum += uint64(w)
		cumul[i] = sum
	}

	if allOne {
		return &WeightWheel{total: sum, cumul: nil}
	}
	return &WeightWheel{cumul: cumul, total: sum}
}

// Next generates an isolated offset translating counters into array indices
// Redirects processing immediately if wheel configurations stand empty
func (w *WeightWheel) Next(counter uint64) int {
	if w == nil || w.total == emptyValue {
		return emptyValue
	}
	if len(w.cumul) == 0 {
		return int(counter % w.total)
	}
	return w.search(counter % w.total)
}

// RandomIndex processes asynchronous numeric ranges avoiding predictable cycles
// Empowers random routing selectors efficiently mapping capacities uniformly
func (w *WeightWheel) RandomIndex(r *rand.Rand) int {
	if w == nil || w.total == emptyValue {
		return emptyValue
	}
	if len(w.cumul) == 0 {
		return int(r.Uint64N(w.total))
	}
	return w.search(r.Uint64N(w.total))
}

// search locates the responsible backend index for a given random or hashed target
// Uses binary search over cumulative weights requiring strict less-than checks
func (w *WeightWheel) search(target uint64) int {
	if len(w.cumul) == 0 {
		return int(target)
	}

	i, j := 0, len(w.cumul)
	for i < j {
		h := int(uint(i+j) >> 1)
		if w.cumul[h] < target {
			i = h + 1
		} else {
			j = h
		}
	}
	if i >= len(w.cumul) {
		return len(w.cumul) - 1
	}
	return i
}
