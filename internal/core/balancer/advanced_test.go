package balancer

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNewAdaptiveSelector covers adaptive selector creation
func TestNewAdaptiveSelector(t *testing.T) {
	t.Run("default learning rate", func(t *testing.T) {
		base := NewSelector([]Backend{}, StrategyRoundRobin)
		a := NewAdaptiveSelector(base, 0.5)
		if a.learningRate != 0.5 {
			t.Errorf("expected learning rate 0.5, got %f", a.learningRate)
		}
	})

	t.Run("clamp negative learning rate", func(t *testing.T) {
		base := NewSelector([]Backend{}, StrategyRoundRobin)
		a := NewAdaptiveSelector(base, -0.1)
		if a.learningRate != 0.1 {
			t.Errorf("expected clamped learning rate 0.1, got %f", a.learningRate)
		}
	})

	t.Run("clamp high learning rate", func(t *testing.T) {
		base := NewSelector([]Backend{}, StrategyRoundRobin)
		a := NewAdaptiveSelector(base, 1.5)
		if a.learningRate != 0.1 {
			t.Errorf("expected clamped learning rate 0.1, got %f", a.learningRate)
		}
	})

	t.Run("initialize performance data map", func(t *testing.T) {
		base := NewSelector([]Backend{}, StrategyRoundRobin)
		a := NewAdaptiveSelector(base, 0.1)
		if a.performanceData == nil {
			t.Error("expected performance data map to be initialized")
		}
	})
}

// TestRecordResult covers metrics recording
func TestRecordResult(t *testing.T) {
	b1 := newMockBackend(1, true, 1)
	base := NewSelector([]Backend{b1}, StrategyRoundRobin)
	a := NewAdaptiveSelector(base, 0.1)

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
		if m.successRate == 0 {
			t.Error("expected non-zero success rate")
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
		if m.consecutiveSuccesses != 0 {
			t.Error("expected consecutive successes to reset")
		}
	})

	t.Run("record latency", func(t *testing.T) {
		// Reset for clean test
		a.performanceData = make(map[Backend]*backendMetrics)
		a.RecordResult(b1, 5000, false)

		a.mu.RLock()
		m := a.performanceData[b1]
		a.mu.RUnlock()

		if m.avgLatency == 0 {
			t.Error("expected latency to be recorded")
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

	t.Run("ema calculation", func(t *testing.T) {
		// Reset
		a.performanceData = make(map[Backend]*backendMetrics)
		a.decayFactor = 0.5 // Higher alpha for testing

		// Record multiple results
		a.RecordResult(b1, 1000, false)
		firstRate := a.performanceData[b1].successRate

		a.RecordResult(b1, 1000, false)
		secondRate := a.performanceData[b1].successRate

		// EMA should approach 1.0 with consecutive successes
		if secondRate <= firstRate {
			t.Error("EMA should increase with consecutive successes")
		}
	})
}

// TestPickAdaptive covers adaptive selection logic
func TestPickAdaptive(t *testing.T) {
	t.Run("exploration returns random", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
		a := NewAdaptiveSelector(base, 1.0) // 100% exploration

		seen := make(map[Backend]bool)
		for i := 0; i < 20; i++ {
			b := a.PickAdaptive(nil, nil)
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
		a := NewAdaptiveSelector(base, 0.0) // 0% exploration

		// Record good performance for b1, bad for b2
		a.RecordResult(b1, 1000, false)
		a.RecordResult(b1, 1000, false)
		a.RecordResult(b2, 10000, true)

		for i := 0; i < 10; i++ {
			if b := a.PickAdaptive(nil, nil); b != b1 {
				t.Error("exploitation should select best performing backend")
			}
		}
	})

	t.Run("skip dead backends", func(t *testing.T) {
		b1 := newMockBackend(1, false, 1)
		b2 := newMockBackend(2, true, 1)
		base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
		a := NewAdaptiveSelector(base, 0.0)

		for i := 0; i < 10; i++ {
			if b := a.PickAdaptive(nil, nil); b != b2 {
				t.Error("should skip dead backends")
			}
		}
	})

	t.Run("new backend gets chance", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
		a := NewAdaptiveSelector(base, 0.0)

		// Only record for b1, b2 is new
		a.RecordResult(b1, 1000, false)

		// Should pick b2 at least once as it's new
		found := false
		for i := 0; i < 10; i++ {
			if b := a.PickAdaptive(nil, nil); b == b2 {
				found = true
				break
			}
		}
		if !found {
			t.Error("new backend should get a chance")
		}
	})

	t.Run("fallback when no metrics", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		base := NewSelector([]Backend{b1}, StrategyRoundRobin)
		a := NewAdaptiveSelector(base, 0.0)

		// Don't record any metrics
		if b := a.PickAdaptive(nil, nil); b != b1 {
			t.Error("should fallback to base selector when no metrics")
		}
	})

	t.Run("nil base pick fallback", func(t *testing.T) {
		b1 := newMockBackend(1, false, 1)
		b2 := newMockBackend(2, false, 1)
		base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
		a := NewAdaptiveSelector(base, 0.0)

		// All dead, should fallback to base Pick which returns nil
		if b := a.PickAdaptive(nil, nil); b != nil {
			t.Error("expected nil when all backends dead")
		}
	})
}

// TestPickAdaptiveWithHash covers hash-based adaptive selection
func TestPickAdaptiveWithHash(t *testing.T) {
	b1 := newMockBackend(1, true, 1)
	b2 := newMockBackend(2, true, 1)
	base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
	a := NewAdaptiveSelector(base, 0.0)

	t.Run("consistent with same key", func(t *testing.T) {
		first := a.PickAdaptiveWithHash(nil, "session-123")
		for i := 0; i < 10; i++ {
			if b := a.PickAdaptiveWithHash(nil, "session-123"); b != first {
				t.Error("same key should return same backend")
			}
		}
	})

	t.Run("different keys may differ", func(t *testing.T) {
		// Just ensure it doesn't panic
		a.PickAdaptiveWithHash(nil, "key1")
		a.PickAdaptiveWithHash(nil, "key2")
	})
}

// TestNewStickySelector covers sticky selector creation
func TestNewStickySelector(t *testing.T) {
	t.Run("default TTL", func(t *testing.T) {
		base := NewSelector([]Backend{}, StrategyRoundRobin)
		s := NewStickySelector(base, 0)
		if s.ttl != 30*time.Minute {
			t.Errorf("expected default TTL 30m, got %v", s.ttl)
		}
	})

	t.Run("custom TTL", func(t *testing.T) {
		base := NewSelector([]Backend{}, StrategyRoundRobin)
		s := NewStickySelector(base, time.Hour)
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
	s := NewStickySelector(base, time.Hour)

	extractor := func(r *http.Request) string {
		if r == nil {
			return ""
		}
		return r.Header.Get("Session-ID")
	}

	t.Run("empty session uses base selector", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		s.PickWithSticky(req, nil, extractor)
		// Should not panic
	})

	t.Run("stick to first selected", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Session-ID", "session-1")

		first := s.PickWithSticky(req, nil, extractor)
		if first == nil {
			t.Fatal("expected backend")
		}

		for i := 0; i < 10; i++ {
			if b := s.PickWithSticky(req, nil, extractor); b != first {
				t.Error("should stick to same backend")
			}
		}
	})

	t.Run("different sessions different backends", func(t *testing.T) {
		req1 := httptest.NewRequest("GET", "/", nil)
		req1.Header.Set("Session-ID", "session-1")
		req2 := httptest.NewRequest("GET", "/", nil)
		req2.Header.Set("Session-ID", "session-2")

		// Both should get a backend (might be same or different)
		b1 := s.PickWithSticky(req1, nil, extractor)
		b2 := s.PickWithSticky(req2, nil, extractor)

		if b1 == nil || b2 == nil {
			t.Error("both sessions should get backends")
		}
	})

	t.Run("backend death triggers reselection", func(t *testing.T) {
		b3 := newMockBackend(3, true, 1)
		b4 := newMockBackend(4, true, 1)
		base2 := NewSelector([]Backend{b3, b4}, StrategyRoundRobin)
		s2 := NewStickySelector(base2, time.Hour)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Session-ID", "session-death")

		first := s2.PickWithSticky(req, nil, extractor)
		first.(*mockBackend).SetAlive(false)

		// Should get different backend now
		second := s2.PickWithSticky(req, nil, extractor)
		if second == first {
			t.Error("should select new backend when sticky one dies")
		}
	})

	// advanced_test.go - Fix the expired session test
	t.Run("expired session reselects", func(t *testing.T) {
		b3 := newMockBackend(3, true, 1)
		b4 := newMockBackend(4, true, 1)
		base2 := NewSelector([]Backend{b3, b4}, StrategyRoundRobin)
		s2 := NewStickySelector(base2, 1*time.Nanosecond) // Very short TTL

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Session-ID", "session-expire")

		// First pick to store the entry
		firstBackend := s2.PickWithSticky(req, nil, extractor)
		if firstBackend == nil {
			t.Fatal("expected backend on first pick")
		}

		// Verify entry was stored
		entry1, ok := s2.stickyTable.Load("session-expire")
		if !ok {
			t.Fatal("entry should exist after first pick")
		}
		expires1 := entry1.(stickyEntry).expires

		time.Sleep(10 * time.Millisecond) // Wait for expiration

		// Second pick - should detect expiration, delete old entry, and create new one
		secondBackend := s2.PickWithSticky(req, nil, extractor)
		if secondBackend == nil {
			t.Fatal("expected backend on second pick")
		}

		// Verify entry still exists (was recreated)
		entry2, ok := s2.stickyTable.Load("session-expire")
		if !ok {
			t.Fatal("entry should exist after second pick (recreated)")
		}
		expires2 := entry2.(stickyEntry).expires

		// The expiration time should be renewed (later than the first one)
		if !expires2.After(expires1) {
			t.Error("expiration should be renewed after re-pick")
		}
	})

	t.Run("nil backend from selector", func(t *testing.T) {
		// All backends dead
		b3 := newMockBackend(3, false, 1)
		base2 := NewSelector([]Backend{b3}, StrategyRoundRobin)
		s2 := NewStickySelector(base2, time.Hour)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Session-ID", "session-nil")

		if b := s2.PickWithSticky(req, nil, extractor); b != nil {
			t.Error("expected nil when no backend available")
		}
	})
}

// TestPickWithStickyHash covers hash-based sticky selection
func TestPickWithStickyHash(t *testing.T) {
	b1 := newMockBackend(1, true, 1)
	b2 := newMockBackend(2, true, 1)
	base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
	s := NewStickySelector(base, time.Hour)

	t.Run("consistent selection", func(t *testing.T) {
		first := s.PickWithStickyHash(nil, "user-123")
		for i := 0; i < 10; i++ {
			if b := s.PickWithStickyHash(nil, "user-123"); b != first {
				t.Error("should be consistent for same key")
			}
		}
	})

	t.Run("stores in sticky table", func(t *testing.T) {
		s.PickWithStickyHash(nil, "user-456")
		if _, ok := s.stickyTable.Load("user-456"); !ok {
			t.Error("should store in sticky table")
		}
	})
}

// TestStickyCleanup covers expired entry cleanup
func TestStickyCleanup(t *testing.T) {
	b1 := newMockBackend(1, true, 1)
	base := NewSelector([]Backend{b1}, StrategyRoundRobin)
	s := NewStickySelector(base, 1*time.Nanosecond)

	// Add expired entry
	s.stickyTable.Store("expired", stickyEntry{
		backendIdx: 0,
		expires:    time.Now().Add(-time.Hour),
	})

	// Add valid entry
	s.stickyTable.Store("valid", stickyEntry{
		backendIdx: 0,
		expires:    time.Now().Add(time.Hour),
	})

	s.Cleanup()

	if _, ok := s.stickyTable.Load("expired"); ok {
		t.Error("expired entry should be deleted")
	}
	if _, ok := s.stickyTable.Load("valid"); !ok {
		t.Error("valid entry should remain")
	}
}

// TestFindBackendIndex covers index lookup
func TestFindBackendIndex(t *testing.T) {
	b1 := newMockBackend(1, true, 1)
	b2 := newMockBackend(2, true, 1)
	base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
	s := NewStickySelector(base, time.Hour)

	t.Run("find existing", func(t *testing.T) {
		idx := s.findBackendIndex(b1)
		if idx != 0 {
			t.Errorf("expected index 0, got %d", idx)
		}
	})

	t.Run("find second", func(t *testing.T) {
		idx := s.findBackendIndex(b2)
		if idx != 1 {
			t.Errorf("expected index 1, got %d", idx)
		}
	})

	t.Run("not found", func(t *testing.T) {
		b3 := newMockBackend(3, true, 1)
		idx := s.findBackendIndex(b3)
		if idx != -1 {
			t.Errorf("expected -1, got %d", idx)
		}
	})
}

// TestConcurrencyAdvanced tests thread safety of advanced selectors
func TestConcurrencyAdvanced(t *testing.T) {
	t.Run("adaptive concurrent", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
		a := NewAdaptiveSelector(base, 0.5)

		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				for j := 0; j < 100; j++ {
					a.PickAdaptive(nil, nil)
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
		s := NewStickySelector(base, time.Hour)

		extractor := func(r *http.Request) string { return "session" }

		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func(id int) {
				for j := 0; j < 100; j++ {
					req := httptest.NewRequest("GET", "/", nil)
					s.PickWithSticky(req, nil, extractor)
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
	a := NewAdaptiveSelector(base, 0.1)

	// Warm up metrics
	a.RecordResult(backends[0], 1000, false)
	a.RecordResult(backends[1], 2000, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.PickAdaptive(nil, nil)
	}
}

func BenchmarkStickyPick(b *testing.B) {
	backends := []Backend{
		newMockBackend(1, true, 1),
		newMockBackend(2, true, 1),
	}
	base := NewSelector(backends, StrategyRoundRobin)
	s := NewStickySelector(base, time.Hour)

	extractor := func(r *http.Request) string { return "bench-session" }
	req := httptest.NewRequest("GET", "/", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.PickWithSticky(req, nil, extractor)
	}
}

func BenchmarkRecordResult(b *testing.B) {
	backends := []Backend{
		newMockBackend(1, true, 1),
	}
	base := NewSelector(backends, StrategyRoundRobin)
	a := NewAdaptiveSelector(base, 0.1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.RecordResult(backends[0], 1000, i%2 == 0)
	}
}
