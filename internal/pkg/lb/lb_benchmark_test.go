package lb

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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

// Benchmarks
func BenchmarkAdaptivePick(b *testing.B) {
	backends := []Backend{
		newMockBackend(1, true, 1),
		newMockBackend(2, true, 1),
	}
	base := NewSelector(backends, StrategyRoundRobin)
	a := NewAdaptive(base, 0.1)

	// Pre-seed metrics
	backends[0].(*mockBackend).SetResponseTime(1000)
	backends[1].(*mockBackend).SetResponseTime(2000)

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

// Algorithms

func BenchmarkPickRoundRobin(b *testing.B) {
	backends := []Backend{
		newMockBackend(1, true, 1),
		newMockBackend(2, true, 1),
		newMockBackend(3, true, 1),
	}
	s := NewSelector(backends, StrategyRoundRobin)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Pick(nil, nil)
	}
}

func BenchmarkPickRandom(b *testing.B) {
	backends := []Backend{
		newMockBackend(1, true, 1),
		newMockBackend(2, true, 1),
		newMockBackend(3, true, 1),
	}
	s := NewSelector(backends, StrategyRandom)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Pick(nil, nil)
	}
}

func BenchmarkPickLeastConn(b *testing.B) {
	backends := []Backend{
		newMockBackend(1, true, 1),
		newMockBackend(2, true, 1),
		newMockBackend(3, true, 1),
	}
	s := NewSelector(backends, StrategyLeastConn)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Pick(nil, nil)
	}
}

func BenchmarkPickWeightedLeastConn(b *testing.B) {
	backends := []Backend{
		newMockBackend(1, true, 10),
		newMockBackend(2, true, 5),
		newMockBackend(3, true, 1),
	}
	s := NewSelector(backends, StrategyWeightedLeastConn)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Pick(nil, nil)
	}
}

func BenchmarkPickIPHash(b *testing.B) {
	backends := []Backend{
		newMockBackend(1, true, 1),
		newMockBackend(2, true, 1),
		newMockBackend(3, true, 1),
	}
	s := NewSelector(backends, StrategyIPHash)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Pick(req, nil)
	}
}

func BenchmarkPickURLHash(b *testing.B) {
	backends := []Backend{
		newMockBackend(1, true, 1),
		newMockBackend(2, true, 1),
		newMockBackend(3, true, 1),
	}
	s := NewSelector(backends, StrategyURLHash)
	req := httptest.NewRequest("GET", "/api/users", nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Pick(req, nil)
	}
}

func BenchmarkPickLeastResponseTime(b *testing.B) {
	backends := []Backend{
		newMockBackend(1, true, 1),
		newMockBackend(2, true, 1),
		newMockBackend(3, true, 1),
	}
	s := NewSelector(backends, StrategyLeastResponseTime)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Pick(nil, nil)
	}
}

func BenchmarkPickPowerOfTwoChoices(b *testing.B) {
	backends := []Backend{
		newMockBackend(1, true, 1),
		newMockBackend(2, true, 1),
		newMockBackend(3, true, 1),
	}
	s := NewSelector(backends, StrategyPowerOfTwoChoices)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Pick(nil, nil)
	}
}

func BenchmarkPickConsistentHash(b *testing.B) {
	backends := []Backend{
		newMockBackend(1, true, 1),
		newMockBackend(2, true, 1),
		newMockBackend(3, true, 1),
	}
	s := NewSelector(backends, StrategyConsistentHash)
	keyFunc := func() uint64 { return uint64(b.N) }
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = s.Pick(nil, keyFunc)
	}
}

// Scalability benchmarks: vary backend count
func BenchmarkPickRoundRobin_Scale(b *testing.B) {
	for _, count := range []int{2, 10, 50, 100} {
		b.Run(fmt.Sprintf("backends_%d", count), func(b *testing.B) {
			backends := make([]Backend, count)
			for i := range count {
				backends[i] = newMockBackend(i, true, 1)
			}
			s := NewSelector(backends, StrategyRoundRobin)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = s.Pick(nil, nil)
			}
		})
	}
}

// Contention benchmark: concurrent picks
func BenchmarkPickConcurrent(b *testing.B) {
	backends := []Backend{
		newMockBackend(1, true, 1),
		newMockBackend(2, true, 1),
		newMockBackend(3, true, 1),
	}
	s := NewSelector(backends, StrategyRoundRobin)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = s.Pick(nil, nil)
		}
	})
}
