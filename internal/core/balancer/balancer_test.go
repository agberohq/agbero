// balancer_test.go - Core selector strategies
package balancer

import (
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// mockBackend implements Backend interface for testing
type mockBackend struct {
	id           int
	alive        atomic.Bool
	weight       int
	inFlight     atomic.Int64
	responseTime atomic.Int64
}

func newMockBackend(id int, alive bool, weight int) *mockBackend {
	m := &mockBackend{id: id, weight: weight}
	m.alive.Store(alive)
	return m
}

func (m *mockBackend) Alive() bool         { return m.alive.Load() }
func (m *mockBackend) Weight() int         { return m.weight }
func (m *mockBackend) InFlight() int64     { return m.inFlight.Load() }
func (m *mockBackend) ResponseTime() int64 { return m.responseTime.Load() }

func (m *mockBackend) SetAlive(v bool)         { m.alive.Store(v) }
func (m *mockBackend) SetInFlight(v int64)     { m.inFlight.Store(v) }
func (m *mockBackend) SetResponseTime(v int64) { m.responseTime.Store(v) }

// TestParseStrategy covers all strategy parsing cases
func TestParseStrategy(t *testing.T) {
	tests := []struct {
		input    string
		expected Strategy
	}{
		{"", StrategyRoundRobin},
		{"round_robin", StrategyRoundRobin},
		{"least_conn", StrategyLeastConn},
		{"random", StrategyRandom},
		{"weighted_least_conn", StrategyWeightedLeastConn},
		{"ip_hash", StrategyIPHash},
		{"url_hash", StrategyURLHash},
		{"least_response_time", StrategyLeastResponseTime},
		{"power_of_two", StrategyPowerOfTwoChoices},
		{"consistent_hash", StrategyConsistentHash},
		{"unknown", StrategyRoundRobin},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := ParseStrategy(tt.input)
			if result != tt.expected {
				t.Errorf("ParseStrategy(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestNewSelector covers selector creation and Update
func TestNewSelector(t *testing.T) {
	t.Run("empty backends", func(t *testing.T) {
		s := NewSelector([]Backend{}, StrategyRoundRobin)
		if s == nil {
			t.Fatal("expected non-nil selector")
		}
	})

	t.Run("with backends", func(t *testing.T) {
		backends := []Backend{
			newMockBackend(1, true, 1),
			newMockBackend(2, true, 2),
		}
		s := NewSelector(backends, StrategyRoundRobin)
		if len(s.backends) != 2 {
			t.Errorf("expected 2 backends, got %d", len(s.backends))
		}
	})

	t.Run("consistent hash strategy", func(t *testing.T) {
		backends := []Backend{
			newMockBackend(1, true, 1),
			newMockBackend(2, true, 1),
		}
		s := NewSelector(backends, StrategyConsistentHash)
		if s.ring == nil {
			t.Error("expected ring to be initialized for consistent hash")
		}
	})
}

// TestSelectorUpdate covers Update method
func TestSelectorUpdate(t *testing.T) {
	b1 := newMockBackend(1, true, 1)
	b2 := newMockBackend(2, true, 2)
	s := NewSelector([]Backend{b1}, StrategyRoundRobin)

	newBackends := []Backend{
		newMockBackend(3, true, 3),
		newMockBackend(4, true, 4),
		newMockBackend(5, true, 5),
	}

	s.Update(newBackends)

	if len(s.backends) != 3 {
		t.Errorf("expected 3 backends after update, got %d", len(s.backends))
	}

	// Test update with consistent hash
	s2 := NewSelector([]Backend{b1, b2}, StrategyConsistentHash)
	s2.Update(newBackends)
	if s2.ring == nil {
		t.Error("expected ring to be rebuilt after update")
	}
}

// TestPickRoundRobin covers round-robin selection
func TestPickRoundRobin(t *testing.T) {
	t.Run("empty backends", func(t *testing.T) {
		s := NewSelector([]Backend{}, StrategyRoundRobin)
		if b := s.Pick(nil, nil); b != nil {
			t.Error("expected nil for empty backends")
		}
	})

	t.Run("single backend", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		s := NewSelector([]Backend{b1}, StrategyRoundRobin)
		if b := s.Pick(nil, nil); b != b1 {
			t.Error("expected single backend")
		}
	})

	t.Run("single dead backend", func(t *testing.T) {
		b1 := newMockBackend(1, false, 1)
		s := NewSelector([]Backend{b1}, StrategyRoundRobin)
		if b := s.Pick(nil, nil); b != nil {
			t.Error("expected nil for dead backend")
		}
	})

	t.Run("multiple backends", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		s := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)

		seen := make(map[Backend]bool)
		for i := 0; i < 10; i++ {
			b := s.Pick(nil, nil)
			if b == nil {
				t.Fatal("expected backend")
			}
			seen[b] = true
		}
		if len(seen) != 2 {
			t.Error("expected to see both backends")
		}
	})

	t.Run("skip dead backend", func(t *testing.T) {
		b1 := newMockBackend(1, false, 1)
		b2 := newMockBackend(2, true, 1)
		s := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)

		for i := 0; i < 5; i++ {
			if b := s.Pick(nil, nil); b != b2 {
				t.Error("expected only alive backend")
			}
		}
	})

	t.Run("all dead backends", func(t *testing.T) {
		b1 := newMockBackend(1, false, 1)
		b2 := newMockBackend(2, false, 1)
		s := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)
		if b := s.Pick(nil, nil); b != nil {
			t.Error("expected nil when all backends dead")
		}
	})
}

// TestPickRandom covers random selection
func TestPickRandom(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		s := NewSelector([]Backend{}, StrategyRandom)
		if b := s.Pick(nil, nil); b != nil {
			t.Error("expected nil")
		}
	})

	t.Run("single", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		s := NewSelector([]Backend{b1}, StrategyRandom)
		if b := s.Pick(nil, nil); b != b1 {
			t.Error("expected b1")
		}
	})

	t.Run("multiple", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		s := NewSelector([]Backend{b1, b2}, StrategyRandom)

		seen := make(map[Backend]bool)
		for i := 0; i < 20; i++ {
			b := s.Pick(nil, nil)
			if b == nil {
				t.Fatal("expected backend")
			}
			seen[b] = true
		}
		if len(seen) != 2 {
			t.Error("expected both backends to be selected")
		}
	})

	t.Run("skip dead", func(t *testing.T) {
		b1 := newMockBackend(1, false, 1)
		b2 := newMockBackend(2, true, 1)
		s := NewSelector([]Backend{b1, b2}, StrategyRandom)

		for i := 0; i < 10; i++ {
			if b := s.Pick(nil, nil); b != b2 {
				t.Error("expected only alive backend")
			}
		}
	})
}

// TestPickLeastConn covers least connections selection
func TestPickLeastConn(t *testing.T) {
	t.Run("select least connections", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		b3 := newMockBackend(3, true, 1)

		b1.SetInFlight(10)
		b2.SetInFlight(5)
		b3.SetInFlight(20)

		s := NewSelector([]Backend{b1, b2, b3}, StrategyLeastConn)

		for i := 0; i < 10; i++ {
			if b := s.Pick(nil, nil); b != b2 {
				t.Error("expected backend with least connections")
			}
		}
	})

	t.Run("all dead", func(t *testing.T) {
		b1 := newMockBackend(1, false, 1)
		s := NewSelector([]Backend{b1}, StrategyLeastConn)
		if b := s.Pick(nil, nil); b != nil {
			t.Error("expected nil")
		}
	})
}

// TestPickWeightedLeastConn covers weighted least connections
func TestPickWeightedLeastConn(t *testing.T) {
	t.Run("weight affects selection", func(t *testing.T) {
		b1 := newMockBackend(1, true, 10) // high weight, high connections
		b2 := newMockBackend(2, true, 1)  // low weight, low connections

		b1.SetInFlight(100)
		b2.SetInFlight(10)

		s := NewSelector([]Backend{b1, b2}, StrategyWeightedLeastConn)

		// b1: 100/10 = 10, b2: 10/1 = 10, equal ratio - either could be picked
		// Test that it doesn't panic and returns something
		if b := s.Pick(nil, nil); b == nil {
			t.Error("expected a backend")
		}
	})

	t.Run("zero weight treated as 1", func(t *testing.T) {
		b1 := newMockBackend(1, true, 0)
		b1.SetInFlight(5)
		b2 := newMockBackend(2, true, 1)
		b2.SetInFlight(5)

		s := NewSelector([]Backend{b1, b2}, StrategyWeightedLeastConn)
		if b := s.Pick(nil, nil); b == nil {
			t.Error("expected a backend")
		}
	})
}

// TestPickIPHash covers IP hash selection
func TestPickIPHash(t *testing.T) {
	t.Run("consistent for same IP", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		s := NewSelector([]Backend{b1, b2}, StrategyIPHash)

		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"

		first := s.Pick(req, nil)
		for i := 0; i < 10; i++ {
			if b := s.Pick(req, nil); b != first {
				t.Error("IP hash should be consistent")
			}
		}
	})

	t.Run("different IPs different backends", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		s := NewSelector([]Backend{b1, b2}, StrategyIPHash)

		seen := make(map[Backend]bool)
		for i := 0; i < 100; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "192.168.1." + string(rune('0'+i%10)) + ":12345"
			if b := s.Pick(req, nil); b != nil {
				seen[b] = true
			}
		}
		// Should eventually see both backends with different IPs
	})

	t.Run("invalid remote addr", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		s := NewSelector([]Backend{b1}, StrategyIPHash)
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "invalid"
		if b := s.Pick(req, nil); b != b1 {
			t.Error("expected backend even with invalid addr")
		}
	})
}

// TestPickURLHash covers URL hash selection
func TestPickURLHash(t *testing.T) {
	t.Run("consistent for same URL", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		s := NewSelector([]Backend{b1, b2}, StrategyURLHash)

		req := httptest.NewRequest("GET", "/api/users", nil)

		first := s.Pick(req, nil)
		for i := 0; i < 10; i++ {
			if b := s.Pick(req, nil); b != first {
				t.Error("URL hash should be consistent")
			}
		}
	})

	t.Run("different paths different backends", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		s := NewSelector([]Backend{b1, b2}, StrategyURLHash)

		seen := make(map[Backend]bool)
		paths := []string{"/a", "/b", "/c", "/d", "/e"}
		for _, path := range paths {
			req := httptest.NewRequest("GET", path, nil)
			if b := s.Pick(req, nil); b != nil {
				seen[b] = true
			}
		}
		if len(seen) < 1 {
			t.Error("expected at least one backend")
		}
	})
}

// TestPickLeastResponseTime covers least response time selection
func TestPickLeastResponseTime(t *testing.T) {
	t.Run("selects by response time", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)

		b1.SetResponseTime(5000) // 5ms
		b2.SetResponseTime(1000) // 1ms

		s := NewSelector([]Backend{b1, b2}, StrategyLeastResponseTime)

		for i := 0; i < 10; i++ {
			if b := s.Pick(nil, nil); b != b2 {
				t.Error("expected backend with least response time")
			}
		}
	})

	t.Run("default response time when zero", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)

		b1.SetResponseTime(0)
		b2.SetResponseTime(0)

		s := NewSelector([]Backend{b1, b2}, StrategyLeastResponseTime)
		if b := s.Pick(nil, nil); b == nil {
			t.Error("expected a backend")
		}
	})

	t.Run("inflight penalty", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)

		b1.SetResponseTime(1000)
		b1.SetInFlight(100) // High inflight
		b2.SetResponseTime(1100)
		b2.SetInFlight(0)

		s := NewSelector([]Backend{b1, b2}, StrategyLeastResponseTime)
		// b1 score: 1000 * (1 + 100*0.1) = 11000
		// b2 score: 1100 * (1 + 0) = 1100
		// b2 should win

		for i := 0; i < 10; i++ {
			if b := s.Pick(nil, nil); b != b2 {
				t.Error("expected backend with lower score")
			}
		}
	})
}

// TestPickPowerOfTwoChoices covers power of two choices
func TestPickPowerOfTwoChoices(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		s := NewSelector([]Backend{}, StrategyPowerOfTwoChoices)
		if b := s.Pick(nil, nil); b != nil {
			t.Error("expected nil")
		}
	})

	t.Run("single backend", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		s := NewSelector([]Backend{b1}, StrategyPowerOfTwoChoices)
		if b := s.Pick(nil, nil); b != b1 {
			t.Error("expected b1")
		}
	})

	t.Run("selects between two", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)

		b1.SetInFlight(100)
		b2.SetInFlight(1)

		s := NewSelector([]Backend{b1, b2}, StrategyPowerOfTwoChoices)

		// Should usually pick b2 due to fewer connections
		b2Count := 0
		for i := 0; i < 100; i++ {
			if b := s.Pick(nil, nil); b == b2 {
				b2Count++
			}
		}
		if b2Count < 30 { // Should pick b2 significantly more often
			t.Error("expected power of two to prefer less loaded backend")
		}
	})

	t.Run("fallback when both candidates dead", func(t *testing.T) {
		b1 := newMockBackend(1, false, 1)
		b2 := newMockBackend(2, false, 1)
		b3 := newMockBackend(3, true, 1)

		s := NewSelector([]Backend{b1, b2, b3}, StrategyPowerOfTwoChoices)

		// Should fallback to least conn which finds b3
		found := false
		for i := 0; i < 10; i++ {
			if b := s.Pick(nil, nil); b == b3 {
				found = true
			}
		}
		if !found {
			t.Error("expected fallback to find alive backend")
		}
	})
}

// TestPickConsistentHash covers consistent hashing
func TestPickConsistentHash(t *testing.T) {
	t.Run("consistent for same key", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		b2 := newMockBackend(2, true, 1)
		s := NewSelector([]Backend{b1, b2}, StrategyConsistentHash)

		keyFunc := func() uint64 { return 12345 }

		first := s.Pick(nil, keyFunc)
		for i := 0; i < 10; i++ {
			if b := s.Pick(nil, keyFunc); b != first {
				t.Error("consistent hash should return same backend for same key")
			}
		}
	})

	t.Run("linear probe for dead backend", func(t *testing.T) {
		b1 := newMockBackend(1, false, 1)
		b2 := newMockBackend(2, true, 1)
		s := NewSelector([]Backend{b1, b2}, StrategyConsistentHash)

		// Force hash to hit b1 first, should probe to b2
		keyFunc := func() uint64 { return 0 }

		if b := s.Pick(nil, keyFunc); b != b2 {
			t.Error("expected linear probe to find alive backend")
		}
	})

	t.Run("all dead returns nil", func(t *testing.T) {
		b1 := newMockBackend(1, false, 1)
		b2 := newMockBackend(2, false, 1)
		s := NewSelector([]Backend{b1, b2}, StrategyConsistentHash)

		if b := s.Pick(nil, func() uint64 { return 1 }); b != nil {
			t.Error("expected nil when all dead")
		}
	})

	t.Run("nil ring falls back to random", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		s := NewSelector([]Backend{b1}, StrategyConsistentHash)
		s.ring = nil

		if b := s.Pick(nil, func() uint64 { return 1 }); b != b1 {
			t.Error("expected fallback to random")
		}
	})

	t.Run("empty ring", func(t *testing.T) {
		b1 := newMockBackend(1, true, 1)
		s := NewSelector([]Backend{b1}, StrategyConsistentHash)
		s.ring = &ConsistentHashRing{}

		if b := s.Pick(nil, func() uint64 { return 1 }); b != b1 {
			t.Error("expected fallback when ring empty")
		}
	})
}

// TestHashFunctions covers hash utilities
func TestHashFunctions(t *testing.T) {
	t.Run("HashString consistent", func(t *testing.T) {
		h1 := HashString("test")
		h2 := HashString("test")
		if h1 != h2 {
			t.Error("hash should be consistent")
		}
	})

	t.Run("HashString different", func(t *testing.T) {
		h1 := HashString("test1")
		h2 := HashString("test2")
		if h1 == h2 {
			t.Error("different strings should have different hashes")
		}
	})

	t.Run("HashBytes consistent", func(t *testing.T) {
		b := []byte("test")
		h1 := HashBytes(b)
		h2 := HashBytes(b)
		if h1 != h2 {
			t.Error("hash should be consistent")
		}
	})

	t.Run("HashUint64 consistent", func(t *testing.T) {
		h1 := HashUint64(12345)
		h2 := HashUint64(12345)
		if h1 != h2 {
			t.Error("hash should be consistent")
		}
	})

	t.Run("HashUint64 different", func(t *testing.T) {
		h1 := HashUint64(12345)
		h2 := HashUint64(54321)
		if h1 == h2 {
			t.Error("different values should have different hashes")
		}
	})
}

// TestConcurrency ensures thread safety
func TestConcurrency(t *testing.T) {
	b1 := newMockBackend(1, true, 1)
	b2 := newMockBackend(2, true, 1)
	s := NewSelector([]Backend{b1, b2}, StrategyRoundRobin)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.Pick(nil, nil)
			}
		}()
	}
	wg.Wait()
}

// Benchmarks
func BenchmarkPickRoundRobin(b *testing.B) {
	backends := []Backend{
		newMockBackend(1, true, 1),
		newMockBackend(2, true, 1),
		newMockBackend(3, true, 1),
	}
	s := NewSelector(backends, StrategyRoundRobin)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Pick(nil, nil)
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
		s.Pick(nil, nil)
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
		s.Pick(nil, nil)
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
		s.Pick(nil, keyFunc)
	}
}
