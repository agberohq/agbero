package lb

import (
	"math/rand/v2"

	"github.com/agberohq/agbero/internal/pkg/raw/asearch"
)

const (
	emptyValue = 0
	unitWeight = 1
)

type WeightWheel struct {
	cumul []uint64
	total uint64
}

// NewWheel constructs a distributed scale mapped directly to backend capacities.
// Normalizes empty variables guarding against zero-sum divisions implicitly.
func NewWheel(weights []int) *WeightWheel {
	if len(weights) == emptyValue {
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

// Next generates an isolated offset translating counters into array indices.
// Redirects processing immediately if wheel configurations stand empty.
func (w *WeightWheel) Next(counter uint64) int {
	if w == nil || w.total == emptyValue {
		return emptyValue
	}
	if len(w.cumul) == emptyValue {
		return int(counter % w.total)
	}
	return asearch.LinearSearch(w.cumul, counter%w.total)
}

// RandomIndex processes asynchronous numeric ranges avoiding predictable cycles.
// Empowers random routing selectors efficiently mapping capacities uniformly.
func (w *WeightWheel) RandomIndex(r *rand.Rand) int {
	if w == nil || w.total == emptyValue {
		return emptyValue
	}
	if len(w.cumul) == emptyValue {
		return int(r.Uint64N(w.total))
	}
	return asearch.LinearSearch(w.cumul, r.Uint64N(w.total))
}

// search finds the first index where cumul[i] > target using LinearSearch.
// Falls back to modulo arithmetic when cumul is nil (uniform weights).
func (w *WeightWheel) search(target uint64) int {
	if len(w.cumul) == emptyValue {
		return int(target % w.total)
	}
	return asearch.LinearSearch(w.cumul, target)
}
