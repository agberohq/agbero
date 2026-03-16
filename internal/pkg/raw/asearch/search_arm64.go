//go:build arm64 && !noasm

package asearch

import "unsafe"

// linearSearchAsm is implemented in highly optimized assembly language.
// Leverages NEON instructions to process multiple array elements simultaneously.
func linearSearchAsm(p unsafe.Pointer, length int, target uint64) int

// sortedSearchAsm is implemented in highly optimized assembly language.
// Leverages NEON instructions to process multiple array elements simultaneously.
func sortedSearchAsm(p unsafe.Pointer, length int, target uint64) int

// linearSearch selects the hardware-accelerated scanning routine if NEON is present.
// Protects against zero-length arrays and unsupported CPU architectures automatically.
func linearSearch(cumul []uint64, target uint64) int {
	if hasNEON && len(cumul) > emptyIndex {
		return linearSearchAsm(unsafe.Pointer(unsafe.SliceData(cumul)), len(cumul), target)
	}
	return linearSearchFallback(cumul, target)
}

// sortedSearch selects the hardware-accelerated search routine if NEON is present.
// Protects against zero-length arrays and unsupported CPU architectures automatically.
func sortedSearch(ring []uint64, key uint64) int {
	if hasNEON && len(ring) > emptyIndex {
		return sortedSearchAsm(unsafe.Pointer(unsafe.SliceData(ring)), len(ring), key)
	}
	return sortedSearchFallback(ring, key)
}
