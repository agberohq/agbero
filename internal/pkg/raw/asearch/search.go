package asearch

// LinearSearch scans sequentially to find the first index where cumul exceeds the target.
// Uses hardware SIMD acceleration on supported platforms for rapid routing resolutions.
func LinearSearch(cumul []uint64, target uint64) int {
	return linearSearch(cumul, target)
}

// SortedSearch performs a binary search to locate the first ring slot matching the key.
// Utilizes optimized instruction pipelines to maintain high-throughput consistent hashing.
func SortedSearch(ring []uint64, key uint64) int {
	return sortedSearch(ring, key)
}
