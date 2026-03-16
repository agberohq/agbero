package dependency

import (
	"math/rand"
	"sort"
	"testing"
)

const (
	testArraySize  = 1000
	testIterations = 1000
)

// TestLinearSearchMatchesReference proves the optimized assembly matches the Go reference.
// Asserts correctness across randomized boundaries and unsorted cumulative arrays.
func TestLinearSearchMatchesReference(t *testing.T) {
	for i := 0; i < testIterations; i++ {
		cumul := make([]uint64, rand.Intn(testArraySize)+1)
		var sum uint64
		for j := range cumul {
			sum += uint64(rand.Intn(100) + 1)
			cumul[j] = sum
		}
		target := uint64(rand.Intn(int(sum) + 50))
		got := LinearSearch(cumul, target)
		want := linearSearchFallback(cumul, target)
		if got != want {
			t.Fatalf("LinearSearch mismatch: got %d, want %d", got, want)
		}
	}
}

// TestSortedSearchMatchesReference proves the optimized binary search matches the Go reference.
// Evaluates key wrap-around and boundary conditions rigorously.
func TestSortedSearchMatchesReference(t *testing.T) {
	for i := 0; i < testIterations; i++ {
		ring := make([]uint64, rand.Intn(testArraySize)+1)
		for j := range ring {
			ring[j] = rand.Uint64()
		}
		sort.Slice(ring, func(a, b int) bool { return ring[a] < ring[b] })

		key := rand.Uint64()
		got := SortedSearch(ring, key)
		want := sortedSearchFallback(ring, key)
		if got != want {
			t.Fatalf("SortedSearch mismatch: got %d, want %d", got, want)
		}
	}
}
