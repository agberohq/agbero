package lb

import (
	"math/rand/v2"
)

// WeightWheel for weighted distribution
type WeightWheel struct {
	cumul []uint64
	total uint64
}

// NewWheel creates a weight distribution wheel
func NewWheel(weights []int) *WeightWheel {
	if len(weights) == 0 {
		return &WeightWheel{}
	}

	cumul := make([]uint64, len(weights))
	var sum uint64
	allOne := true

	for i, w := range weights {
		if w <= 0 {
			w = 1
		}
		if w != 1 {
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

// Next returns index for round-robin with weight
func (w *WeightWheel) Next(counter uint64) int {
	if w == nil || w.total == 0 {
		return 0
	}
	if len(w.cumul) == 0 {
		return int(counter % w.total)
	}
	return w.search(counter % w.total)
}

// RandomIndex returns random weighted index
func (w *WeightWheel) RandomIndex(r *rand.Rand) int {
	if w == nil || w.total == 0 {
		return 0
	}
	if len(w.cumul) == 0 {
		return int(r.Uint64N(w.total))
	}
	return w.search(r.Uint64N(w.total))
}

// Search finds bucket for target value using binary search
func (w *WeightWheel) search(target uint64) int {
	if len(w.cumul) == 0 {
		return int(target)
	}

	i, j := 0, len(w.cumul)
	for i < j {
		h := int(uint(i+j) >> 1)
		if w.cumul[h] <= target {
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
