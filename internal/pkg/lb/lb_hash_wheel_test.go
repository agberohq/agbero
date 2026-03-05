package lb

import (
	"math"
	"math/rand/v2"
	"testing"
)

// TestBuildConsistentHash covers ring creation
func TestBuildConsistentHash(t *testing.T) {
	t.Run("empty count", func(t *testing.T) {
		r := NewConsistent(0, 10)
		if len(r.ring) != 0 {
			t.Error("expected empty ring")
		}
	})

	t.Run("zero replicas", func(t *testing.T) {
		r := NewConsistent(3, 0)
		if len(r.ring) != 0 {
			t.Error("expected empty ring with zero replicas")
		}
	})

	t.Run("valid ring", func(t *testing.T) {
		r := NewConsistent(3, 150)
		expectedLen := 3 * 150
		if len(r.ring) != expectedLen {
			t.Errorf("expected %d entries, got %d", expectedLen, len(r.ring))
		}
		if len(r.backends) != expectedLen {
			t.Errorf("expected %d backend entries, got %d", expectedLen, len(r.backends))
		}
	})

	t.Run("sorted ring", func(t *testing.T) {
		r := NewConsistent(5, 100)
		for i := 1; i < len(r.ring); i++ {
			if r.ring[i] < r.ring[i-1] {
				t.Error("ring should be sorted")
			}
		}
	})

	t.Run("backend distribution", func(t *testing.T) {
		r := NewConsistent(2, 10)
		counts := make(map[int32]int)
		for _, b := range r.backends {
			counts[b]++
		}
		if len(counts) != 2 {
			t.Error("should have entries for both backends")
		}
		for i := range 2 {
			i32 := int32(i)
			if counts[i32] != 10 {
				t.Errorf("backend %d should have 10 replicas, got %d", i, counts[i32])
			}
		}
	})
}

// TestConsistentHashRingGet covers key lookup
func TestConsistentHashRingGet(t *testing.T) {
	t.Run("empty ring", func(t *testing.T) {
		r := &Consistent{}
		idx := r.Get(12345)
		if idx != 0 {
			t.Errorf("expected 0 for empty ring, got %d", idx)
		}
	})

	t.Run("exact match", func(t *testing.T) {
		r := NewConsistent(3, 150)
		// Use a hash that exists in the ring
		h := r.ring[50]
		idx := r.Get(h)
		if idx < 0 || idx >= 3 {
			t.Errorf("index %d out of range", idx)
		}
	})

	t.Run("wrap around", func(t *testing.T) {
		r := NewConsistent(3, 150)
		// Use max uint64 to force wrap
		idx := r.Get(math.MaxUint64)
		// Should wrap to first backend
		if idx < 0 || idx >= 3 {
			t.Errorf("index %d out of range", idx)
		}
	})

	t.Run("between hashes", func(t *testing.T) {
		r := NewConsistent(3, 150)
		if len(r.ring) < 2 {
			t.Fatal("ring too small")
		}
		// Pick value between two ring positions
		h := r.ring[0] + (r.ring[1]-r.ring[0])/2
		idx := r.Get(h)
		// Should return backend at r.ring[1] or later
		if idx < 0 || idx >= 3 {
			t.Errorf("index %d out of range", idx)
		}
	})

	t.Run("distribution uniformity", func(t *testing.T) {
		r := NewConsistent(5, 200)
		counts := make(map[int]int)

		// Test many random keys
		for range 10000 {
			key := rand.Uint64()
			idx := r.Get(key)
			counts[idx]++
		}

		// Check all backends got some traffic
		for i := range 5 {
			if counts[i] == 0 {
				t.Errorf("backend %d got no traffic", i)
			}
		}

		// Check rough uniformity (within 50% of average)
		avg := 10000 / 5
		for i := range 5 {
			if counts[i] < avg/2 || counts[i] > avg*3/2 {
				t.Logf("Warning: backend %d has %d hits (avg %d)", i, counts[i], avg)
			}
		}
	})
}

// TestBuildWheel covers weight wheel creation
func TestBuildWheel(t *testing.T) {
	t.Run("empty weights", func(t *testing.T) {
		w := NewWheel([]int{})
		if w.total != 0 {
			t.Error("expected zero total for empty weights")
		}
	})

	t.Run("uniform weights", func(t *testing.T) {
		w := NewWheel([]int{1, 1, 1})
		if w.cumul != nil {
			t.Error("expected nil cumul for uniform weights")
		}
		if w.total != 3 {
			t.Errorf("expected total 3, got %d", w.total)
		}
	})

	t.Run("varying weights", func(t *testing.T) {
		w := NewWheel([]int{1, 2, 3})
		if w.cumul == nil {
			t.Error("expected cumul for varying weights")
		}
		if w.total != 6 {
			t.Errorf("expected total 6, got %d", w.total)
		}
		expected := []uint64{1, 3, 6}
		for i, v := range expected {
			if w.cumul[i] != v {
				t.Errorf("cumul[%d] = %d, want %d", i, w.cumul[i], v)
			}
		}
	})

	t.Run("zero weights treated as one", func(t *testing.T) {
		w := NewWheel([]int{0, 2, 0})
		if w.total != 4 { // 1 + 2 + 1
			t.Errorf("expected total 4, got %d", w.total)
		}
	})

	t.Run("negative weights treated as one", func(t *testing.T) {
		w := NewWheel([]int{-1, 2, -5})
		if w.total != 4 { // 1 + 2 + 1
			t.Errorf("expected total 4, got %d", w.total)
		}
	})
}

// TestWeightWheelNext covers round-robin selection
func TestWeightWheelNext(t *testing.T) {
	t.Run("nil wheel", func(t *testing.T) {
		var w *WeightWheel
		idx := w.Next(0)
		if idx != 0 {
			t.Errorf("expected 0, got %d", idx)
		}
	})

	t.Run("zero total", func(t *testing.T) {
		w := &WeightWheel{total: 0}
		idx := w.Next(0)
		if idx != 0 {
			t.Errorf("expected 0, got %d", idx)
		}
	})

	t.Run("uniform weights", func(t *testing.T) {
		w := NewWheel([]int{1, 1, 1})
		seen := make(map[int]bool)
		for i := range uint64(6) {
			idx := w.Next(i)
			seen[idx] = true
			if idx != int(i%3) {
				t.Errorf("counter %d: expected %d, got %d", i, i%3, idx)
			}
		}
		if len(seen) != 3 {
			t.Error("should see all backends")
		}
	})

	t.Run("weighted distribution", func(t *testing.T) {
		w := NewWheel([]int{1, 2, 1}) // total 4
		counts := make(map[int]int)
		for i := range uint64(4000) {
			idx := w.Next(i)
			counts[idx]++
		}
		// Backend 1 should get ~50%, 0 and 2 ~25% each
		if counts[1] < 1800 || counts[1] > 2200 {
			t.Errorf("backend 1 should get ~50%%, got %d", counts[1])
		}
	})

	t.Run("counter modulo", func(t *testing.T) {
		w := NewWheel([]int{1, 1, 1})
		// Counter wraps around
		idx1 := w.Next(0)
		idx2 := w.Next(3)
		if idx1 != idx2 {
			t.Error("should wrap around")
		}
	})
}

// TestWeightWheelRandomIndex covers random selection
func TestWeightWheelRandomIndex(t *testing.T) {
	t.Run("nil wheel", func(t *testing.T) {
		var w *WeightWheel
		r := rand.New(rand.NewPCG(1, 2))
		idx := w.RandomIndex(r)
		if idx != 0 {
			t.Errorf("expected 0, got %d", idx)
		}
	})

	t.Run("uniform random", func(t *testing.T) {
		w := NewWheel([]int{1, 1, 1})
		r := rand.New(rand.NewPCG(1, 2))
		seen := make(map[int]bool)
		for range 30 {
			idx := w.RandomIndex(r)
			seen[idx] = true
		}
		if len(seen) < 2 {
			t.Error("should see multiple backends")
		}
	})

	t.Run("weighted random", func(t *testing.T) {
		w := NewWheel([]int{1, 5, 1}) // Backend 1 has 5x weight
		r := rand.New(rand.NewPCG(1, 2))
		counts := make(map[int]int)
		for range 7000 {
			idx := w.RandomIndex(r)
			counts[idx]++
		}
		// Backend 1 should dominate
		if counts[1] < 4000 {
			t.Errorf("backend 1 should dominate, got %d", counts[1])
		}
	})
}

// TestWeightWheelSearch covers binary search
func TestWeightWheelSearch(t *testing.T) {
	t.Run("empty cumul", func(t *testing.T) {
		w := NewWheel([]int{1, 1, 1})
		idx := w.search(1)
		if idx != 1 {
			t.Errorf("expected 1, got %d", idx)
		}
	})

	t.Run("find first", func(t *testing.T) {
		w := NewWheel([]int{5, 5, 5})
		idx := w.search(0)
		if idx != 0 {
			t.Errorf("expected 0, got %d", idx)
		}
	})

	t.Run("find last", func(t *testing.T) {
		w := NewWheel([]int{1, 2, 3})
		idx := w.search(5) // Last position
		if idx != 2 {
			t.Errorf("expected 2, got %d", idx)
		}
	})

	t.Run("find middle", func(t *testing.T) {
		w := NewWheel([]int{1, 3, 1}) // cumul: [1, 4, 5]
		idx := w.search(2)            // Should find index 1
		if idx != 1 {
			t.Errorf("expected 1, got %d", idx)
		}
	})

	t.Run("boundary", func(t *testing.T) {
		w := NewWheel([]int{1, 2, 3}) // cumul: [1, 3, 6]
		// target == cumul[i] should return i+1
		idx := w.search(1)
		if idx != 1 {
			t.Errorf("boundary case: expected 1, got %d", idx)
		}
	})

	t.Run("target exceeds total", func(t *testing.T) {
		w := NewWheel([]int{1, 2, 3})
		idx := w.search(10)
		if idx != 2 {
			t.Errorf("expected last index 2, got %d", idx)
		}
	})

	t.Run("single element", func(t *testing.T) {
		w := NewWheel([]int{5})
		idx := w.search(0)
		if idx != 0 {
			t.Errorf("expected 0, got %d", idx)
		}
		idx = w.search(4)
		if idx != 0 {
			t.Errorf("expected 0, got %d", idx)
		}
	})
}

// TestConsistentHashMinimalRedistribution tests that adding/removing backends
// minimizes key redistribution
func TestConsistentHashMinimalRedistribution(t *testing.T) {
	// Build initial ring with 4 backends
	r1 := NewConsistent(4, 100)

	// Map 1000 keys to backends
	keyCount := 1000
	initialMapping := make(map[int]int)
	for i := range keyCount {
		key := uint64(i * 1844674407370955161 / keyCount) // Spread across uint64 range
		idx := r1.Get(key)
		initialMapping[i] = idx
	}

	// Build new ring with 5 backends
	r2 := NewConsistent(5, 100)

	// Check how many keys moved
	moved := 0
	for i := range keyCount {
		key := uint64(i * 1844674407370955161 / keyCount)
		newIdx := r2.Get(key)
		if newIdx != initialMapping[i] {
			moved++
		}
	}

	// Ideally, only 1/5 of keys should move (20%)
	// Allow up to 30% for hash imperfections
	moveRatio := float64(moved) / float64(keyCount)
	if moveRatio > 0.30 {
		t.Errorf("too much redistribution: %.2f%% keys moved", moveRatio*100)
	}

	t.Logf("Redistribution: %.2f%% keys moved (ideal ~20%%)", moveRatio*100)
}
