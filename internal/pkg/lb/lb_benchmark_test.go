package lb

import (
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Benchmarks
func BenchmarkAdaptivePick(b *testing.B) {
	backends := []Backend{
		newMockBackend(1, true, 1),
		newMockBackend(2, true, 1),
	}
	base := NewSelector(backends, StrategyRoundRobin)
	a := NewAdaptive(base, 0.1)

	// Warm up metrics
	a.RecordResult(backends[0], 1000, false)
	a.RecordResult(backends[1], 2000, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Pick(nil, nil)
	}
}

func BenchmarkStickyPick(b *testing.B) {
	backends := []Backend{
		newMockBackend(1, true, 1),
		newMockBackend(2, true, 1),
	}
	base := NewSelector(backends, StrategyRoundRobin)

	extractor := func(r *http.Request) string { return "bench-session" }
	s := NewSticky(base, time.Hour, extractor)
	req := httptest.NewRequest("GET", "/", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Pick(req, nil)
	}
}

func BenchmarkRecordResult(b *testing.B) {
	backends := []Backend{
		newMockBackend(1, true, 1),
	}
	base := NewSelector(backends, StrategyRoundRobin)
	a := NewAdaptive(base, 0.1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.RecordResult(backends[0], 1000, i%2 == 0)
	}
}

// Benchmarks
func BenchmarkConsistentHashBuild(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewConsistent(10, 150)
	}
}

func BenchmarkConsistentHashGet(b *testing.B) {
	r := NewConsistent(10, 150)
	keys := make([]uint64, 1000)
	for i := range keys {
		keys[i] = rand.Uint64()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Get(keys[i%1000])
	}
}

func BenchmarkWeightWheelNext(b *testing.B) {
	w := NewWheel([]int{1, 2, 3, 4, 5})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Next(uint64(i))
	}
}

func BenchmarkWeightWheelSearch(b *testing.B) {
	w := NewWheel([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	targets := make([]uint64, 1000)
	for i := range targets {
		targets[i] = rand.Uint64N(w.total)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.search(targets[i%1000])
	}
}

func BenchmarkWeightWheelRandomIndex(b *testing.B) {
	w := NewWheel([]int{1, 2, 3, 4, 5})
	r := rand.New(rand.NewPCG(1, 2))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.RandomIndex(r)
	}
}
