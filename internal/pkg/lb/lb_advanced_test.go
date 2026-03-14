package lb

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cespare/xxhash/v2"
)

// TestNewAdaptive covers adaptive selector creation
func TestNewAdaptive(t *testing.T) {
	t.Run("default learning rate", func(t *testing.T) {
		base := NewSelector([]Backend{}, StrategyRoundRobin)
		a := NewAdaptive(base, 0.5)
		if a.learningRate != 0.5 {
			t.Errorf("expected learning rate 0.5, got %f", a.learningRate)
		}
	})

	t.Run("clamp invalid learning rate", func(t *testing.T) {
		base := NewSelector([]Backend{}, StrategyRoundRobin)
		a := NewAdaptive(base, -0.1)
		if a.learningRate != 0.15 {
			t.Errorf("expected clamped learning rate 0.15, got %f", a.learningRate)
		}
		a2 := NewAdaptive(base, 1.5)
		if a2.learningRate != 0.15 {
			t.Errorf("expected clamped learning rate 0.15, got %f", a2.learningRate)
		}
	})
}

// TestPickAdaptive covers adaptive selection logic
func TestPickAdaptive(t *testing.T) {
	t.Run("exploration returns via base strategy", func(t *testing.T) {
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
			t.Error("100% exploration should see both backends via RR")
		}
	})

	t.Run("exploitation selects best by response time", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
		a := NewAdaptive(base, 0.0) // 0% exploration

		// b1 is faster than b2
		b1.SetResponseTime(1000)
		b2.SetResponseTime(5000)

		for range 10 {
			if b := a.Pick(nil, nil); b != b1 {
				t.Error("exploitation should select backend with lower response time")
			}
		}
	})

	t.Run("exploitation considers inflight penalty", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
		a := NewAdaptive(base, 0.0)

		// Same response time, but b1 has high inflight
		b1.SetResponseTime(1000)
		b1.SetInFlight(100)
		b2.SetResponseTime(1000)
		b2.SetInFlight(0)

		// b2 should win due to lower concurrency penalty
		for range 10 {
			if b := a.Pick(nil, nil); b != b2 {
				t.Error("exploitation should prefer backend with lower inflight")
			}
		}
	})

	t.Run("zero response time gets baseline", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
		a := NewAdaptive(base, 0.0)

		// b1 has no data (0), b2 has measured latency
		b1.SetResponseTime(0)
		b2.SetResponseTime(2000)

		// b1 gets baseline 1000, which beats b2's 2000
		for range 10 {
			if b := a.Pick(nil, nil); b != b1 {
				t.Error("backend with no data should get baseline penalty and be preferred over slow backend")
			}
		}
	})

	t.Run("fallback when all unusable", func(t *testing.T) {
		b1 := newMockBackend(1, false, 1)
		b2 := newMockBackend(2, false, 1)
		base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
		a := NewAdaptive(base, 0.0)

		// Should fallback to base strategy which returns nil for dead backends
		if b := a.Pick(nil, nil); b != nil {
			t.Error("expected nil when all backends unusable")
		}
	})

	t.Run("single backend bypasses scoring", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		base := NewSelector([]Backend{b1}, StrategyRoundRobin)
		a := NewAdaptive(base, 0.0)

		if b := a.Pick(nil, nil); b != b1 {
			t.Error("expected single backend")
		}
	})

	t.Run("single dead backend returns nil", func(t *testing.T) {
		b1 := newMockBackend(1, false, 1)
		base := NewSelector([]Backend{b1}, StrategyRoundRobin)
		a := NewAdaptive(base, 0.0)

		if b := a.Pick(nil, nil); b != nil {
			t.Error("expected nil for single dead backend")
		}
	})
}

// TestPickAdaptiveWithHash covers hash-based adaptive selection
func TestPickAdaptiveWithHash(t *testing.T) {
	b1 := newMockBackend(1, true, 1)
	b2 := newMockBackend(2, true, 1)

	keyFunc := func() uint64 { return xxhash.Sum64String("session-123") }

	t.Run("exploration respects base strategy consistency", func(t *testing.T) {
		// With 100% exploration, should delegate to ConsistentHash
		aExp := NewAdaptive(NewSelector([]Backend{b1, b2}, StrategyConsistentHash), 1.0)
		first := aExp.Pick(nil, keyFunc)
		for range 10 {
			if b := aExp.Pick(nil, keyFunc); b != first {
				t.Error("exploration should preserve base strategy consistency")
			}
		}
	})
}

// TestAdaptiveUpdate covers backend list updates
func TestAdaptiveUpdate(t *testing.T) {
	b1 := newMockBackend(1, true, 1)
	base := NewSelector([]Backend{b1}, StrategyRoundRobin)
	a := NewAdaptive(base, 0.0)

	b2 := newMockBackend(2, true, 1)
	b3 := newMockBackend(3, true, 1)
	a.Update([]Backend{b2, b3})

	backends := a.Backends()
	if len(backends) != 2 {
		t.Errorf("expected 2 backends after update, got %d", len(backends))
	}
}

// TestAdaptiveStop covers graceful shutdown
func TestAdaptiveStop(t *testing.T) {
	b1 := newMockBackend(1, true, 1)
	base := NewSelector([]Backend{b1}, StrategyRoundRobin)
	a := NewAdaptive(base, 0.1)

	// Should not panic
	a.Stop()
	a.Stop() // Idempotent
}

// TestConcurrencyAdvanced tests thread safety of advanced selectors
func TestConcurrencyAdvanced(t *testing.T) {
	t.Run("adaptive concurrent", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		base := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
		a := NewAdaptive(base, 0.5)

		// Pre-seed metrics for exploitation path
		b1.SetResponseTime(1000)
		b2.SetResponseTime(2000)

		done := make(chan bool)
		for range 10 {
			go func() {
				for range 100 {
					a.Pick(nil, nil)
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
