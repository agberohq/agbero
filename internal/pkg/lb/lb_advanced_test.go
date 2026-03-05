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
		for range 20 {
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

		for range 10 {
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
		for range 20 {
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
		for range 10 {
			if b := a.Pick(nil, keyFunc); b != first {
				t.Error("same key should return same backend")
			}
		}
	})
}

// TestConcurrencyAdvanced tests thread safety of advanced selectors
func TestConcurrencyAdvanced(t *testing.T) {
	t.Run("adaptive concurrent", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
		a := NewAdaptive(base, 0.5)

		done := make(chan bool)
		for range 10 {
			go func() {
				for range 100 {
					a.Pick(nil, nil)
					a.RecordResult(b1, 1000, false)
				}
				done <- true
			}()
		}
		for range 10 {
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
		for i := range 10 {
			go func(id int) {
				for range 100 {
					req := httptest.NewRequest("GET", "/", nil)
					s.Pick(req, nil)
				}
				done <- true
			}(i)
		}
		for range 10 {
			<-done
		}
	})
}
