//go:build (!amd64 && !arm64) || noasm

package dependency

// linearSearch delegates the execution directly to the pure Go implementation.
// Invoked exclusively on platforms lacking specific assembly optimizations.
func linearSearch(cumul []uint64, target uint64) int {
	return linearSearchFallback(cumul, target)
}

// sortedSearch delegates the execution directly to the pure Go implementation.
// Invoked exclusively on platforms lacking specific assembly optimizations.
func sortedSearch(ring []uint64, key uint64) int {
	return sortedSearchFallback(ring, key)
}
