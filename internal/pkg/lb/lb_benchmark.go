package lb

import (
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
