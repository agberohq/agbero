package lb

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cespare/xxhash/v2"
)

// TestNewAdaptiveSelector covers adaptive selector creation
func TestNewAdaptiveSelector(t *testing.T) {
	t.Run("default learning rate", func(t *testing.T) {
		base := NewSelector([]Backend{}, StrategyRoundRobin)
		a := NewAdaptive(base, 0.5)
		if a.learningRate != 0.5 {
			t.Errorf("expected learning rate 0.5, got %f", a.learningRate)
		}
	})

	t.Run("clamp negative learning rate", func(t *testing.T) {
		base := NewSelector([]Backend{}, StrategyRoundRobin)
		a := NewAdaptive(base, -0.1)
		if a.learningRate != 0.1 {
			t.Errorf("expected clamped learning rate 0.1, got %f", a.learningRate)
		}
	})

	t.Run("initialize performance data map", func(t *testing.T) {
		base := NewSelector([]Backend{}, StrategyRoundRobin)
		a := NewAdaptive(base, 0.1)
		if a.performanceData == nil {
			t.Error("expected performance data map to be initialized")
		}
	})
}

// TestRecordResult covers metrics recording
func TestRecordResult(t *testing.T) {
	b1 := newMockBackend(1, true, 1)
	base := NewSelector([]Backend{b1}, StrategyRoundRobin)
	a := NewAdaptive(base, 0.1)

	t.Run("record success", func(t *testing.T) {
		a.RecordResult(b1, 1000, false)

		a.mu.RLock()
		m := a.performanceData[b1]
		a.mu.RUnlock()

		if m == nil {
			t.Fatal("expected metrics to exist")
		}
		if m.requestCount != 1 {
			t.Errorf("expected 1 request, got %d", m.requestCount)
		}
		if m.failureCount != 0 {
			t.Errorf("expected 0 failures, got %d", m.failureCount)
		}
	})

	t.Run("record failure", func(t *testing.T) {
		a.RecordResult(b1, 1000, true)

		a.mu.RLock()
		m := a.performanceData[b1]
		a.mu.RUnlock()

		if m.failureCount == 0 {
			t.Error("expected failure to be recorded")
		}
	})

	t.Run("create metrics if not exists", func(t *testing.T) {
		b2 := newMockBackend(2, true, 1)
		a.RecordResult(b2, 1000, false)

		a.mu.RLock()
		_, exists := a.performanceData[b2]
		a.mu.RUnlock()

		if !exists {
			t.Error("expected metrics to be created for new backend")
		}
	})
}

// TestPickAdaptive covers adaptive selection logic
func TestPickAdaptive(t *testing.T) {
	t.Run("exploration returns random", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
		a := NewAdaptive(base, 1.0) // 100% exploration

		seen := make(map[Backend]bool)
		for i := 0; i < 20; i++ {
			b := a.Pick(nil, nil)
			if b != nil {
				seen[b] = true
			}
		}
		if len(seen) != 2 {
			t.Error("100% exploration should see both backends")
		}
	})

	t.Run("exploitation selects best", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
		a := NewAdaptive(base, 0.0) // 0% exploration (but will force exploration if backends unknown)

		// Must register backends so Adaptive knows about them via Update
		a.Update([]Backend{b1, b2})

		// Record good performance for b1, bad for b2
		a.RecordResult(b1, 1000, false)
		a.RecordResult(b1, 1000, false)
		a.RecordResult(b2, 10000, true)

		for i := 0; i < 10; i++ {
			if b := a.Pick(nil, nil); b != b1 {
				t.Error("exploitation should select best performing backend")
			}
		}
	})

	t.Run("new backend gets chance", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
		a := NewAdaptive(base, 0.0)

		// Important: Register both backends
		a.Update([]Backend{b1, b2})

		// Only record for b1. b2 is in allBackends but not performanceData.
		a.RecordResult(b1, 1000, false)

		// Logic: len(perf) < len(all), so Pick forces exploration (fallback to base).
		// Base is RR, so it will eventually pick b2.
		found := false
		for i := 0; i < 20; i++ {
			if b := a.Pick(nil, nil); b == b2 {
				found = true
				break
			}
		}
		if !found {
			t.Error("new backend should get a chance via forced exploration")
		}
	})
}

// TestPickAdaptiveWithHash covers hash-based adaptive selection
func TestPickAdaptiveWithHash(t *testing.T) {
	b1 := newMockBackend(1, true, 1)
	b2 := newMockBackend(2, true, 1)

	//  Use ConsistentHash strategy. RoundRobin ignores keys.
	base := NewSelector([]Backend{b1, b2}, StrategyConsistentHash)
	a := NewAdaptive(base, 0.0)
	a.Update([]Backend{b1, b2})

	keyFunc := func() uint64 { return xxhash.Sum64String("session-123") }

	t.Run("consistent with same key", func(t *testing.T) {
		// Since we have no metrics, Adaptive falls back to Base (ConsistentHash)
		first := a.Pick(nil, keyFunc)
		for i := 0; i < 10; i++ {
			if b := a.Pick(nil, keyFunc); b != first {
				t.Error("same key should return same backend")
			}
		}
	})
}

// TestNewStickySelector covers sticky selector creation
func TestNewStickySelector(t *testing.T) {
	t.Run("default TTL", func(t *testing.T) {
		base := NewSelector([]Backend{}, StrategyRoundRobin)
		s := NewSticky(base, 0, nil)
		if s.ttl != 30*time.Minute {
			t.Errorf("expected default TTL 30m, got %v", s.ttl)
		}
	})

	t.Run("custom TTL", func(t *testing.T) {
		base := NewSelector([]Backend{}, StrategyRoundRobin)
		s := NewSticky(base, time.Hour, nil)
		if s.ttl != time.Hour {
			t.Errorf("expected TTL 1h, got %v", s.ttl)
		}
	})
}

// TestPickWithSticky covers sticky session selection
func TestPickWithSticky(t *testing.T) {
	b1 := newMockBackend(1, true, 1)
	b2 := newMockBackend(2, true, 1)
	base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)

	extractor := func(r *http.Request) string {
		if r == nil {
			return ""
		}
		return r.Header.Get("Session-ID")
	}

	s := NewSticky(base, time.Hour, extractor)

	t.Run("stick to first selected", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Session-ID", "session-1")

		first := s.Pick(req, nil)
		if first == nil {
			t.Fatal("expected backend")
		}

		for i := 0; i < 10; i++ {
			if b := s.Pick(req, nil); b != first {
				t.Error("should stick to same backend")
			}
		}
	})

	t.Run("expired session reselects", func(t *testing.T) {
		b3 := newMockBackend(3, true, 1)
		b4 := newMockBackend(4, true, 1)
		base2 := NewSelector([]Backend{b3, b4}, StrategyRoundRobin)

		//  Use a larger TTL that we can reliably wait for
		s2 := NewSticky(base2, 50*time.Millisecond, extractor)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Session-ID", "session-expire")

		firstBackend := s2.Pick(req, nil)
		if firstBackend == nil {
			t.Fatal("expected backend")
		}

		// Verify entry stored
		entry1, ok := s2.stickyTable.Load("session-expire")
		if !ok {
			t.Fatal("entry should exist")
		}
		expires1 := entry1.(stickyEntry).expires

		// Wait for expiration
		time.Sleep(100 * time.Millisecond)

		// Should detect expiration, delete, and re-pick
		secondBackend := s2.Pick(req, nil)
		if secondBackend == nil {
			t.Fatal("expected backend")
		}

		// Verify entry was refreshed
		entry2, ok := s2.stickyTable.Load("session-expire")
		if !ok {
			t.Fatal("entry should exist after re-pick")
		}
		expires2 := entry2.(stickyEntry).expires

		if !expires2.After(expires1) {
			t.Error("expiration should be renewed after re-pick")
		}
	})
}

// TestStickyCleanup covers expired entry cleanup
func TestStickyCleanup(t *testing.T) {
	b1 := newMockBackend(1, true, 1)
	base := NewSelector([]Backend{b1}, StrategyRoundRobin)
	s := NewSticky(base, 1*time.Nanosecond, nil)

	// Add expired entry
	s.stickyTable.Store("expired", stickyEntry{
		backend: b1,
		expires: time.Now().Add(-time.Hour),
	})

	// Add valid entry
	s.stickyTable.Store("valid", stickyEntry{
		backend: b1,
		expires: time.Now().Add(time.Hour),
	})

	s.Cleanup()

	if _, ok := s.stickyTable.Load("expired"); ok {
		t.Error("expired entry should be deleted")
	}
	if _, ok := s.stickyTable.Load("valid"); !ok {
		t.Error("valid entry should remain")
	}
}

// TestConcurrencyAdvanced tests thread safety of advanced selectors
func TestConcurrencyAdvanced(t *testing.T) {
	t.Run("adaptive concurrent", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
		a := NewAdaptive(base, 0.5)

		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				for j := 0; j < 100; j++ {
					a.Pick(nil, nil)
					a.RecordResult(b1, 1000, false)
				}
				done <- true
			}()
		}
		for i := 0; i < 10; i++ {
			<-done
		}
	})

	t.Run("sticky concurrent", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)

		extractor := func(r *http.Request) string { return "session" }
		s := NewSticky(base, time.Hour, extractor)

		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func(id int) {
				for j := 0; j < 100; j++ {
					req := httptest.NewRequest("GET", "/", nil)
					s.Pick(req, nil)
				}
				done <- true
			}(i)
		}
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}

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
