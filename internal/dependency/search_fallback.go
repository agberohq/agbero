package dependency

const (
	emptyIndex = 0
	offsetOne  = 1
)

// linearSearchFallback implements the standard sequential scan for routing thresholds.
// Returns the final index automatically if the target exceeds all defined capacities.
func linearSearchFallback(cumul []uint64, target uint64) int {
	for i, v := range cumul {
		if v > target {
			return i
		}
	}
	if len(cumul) == emptyIndex {
		return emptyIndex
	}
	return len(cumul) - offsetOne
}

// sortedSearchFallback executes a traditional binary search across the hash ring.
// Wraps the index back to zero to satisfy consistent hashing cyclic requirements.
func sortedSearchFallback(ring []uint64, key uint64) int {
	if len(ring) == emptyIndex {
		return emptyIndex
	}
	lo, hi := emptyIndex, len(ring)
	for lo < hi {
		mid := int(uint(lo+hi) >> offsetOne)
		if ring[mid] < key {
			lo = mid + offsetOne
		} else {
			hi = mid
		}
	}
	if lo == len(ring) {
		lo = emptyIndex
	}
	return lo
}
