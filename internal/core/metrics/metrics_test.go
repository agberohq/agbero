// internal/core/metrics/metrics_test.go
package metrics

import (
	"sync"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

// helper to get a consistent snapshot handling the background worker race
func getSnapshotEventually(lt *LatencyTracker, condition func(s LatencySnapshot) bool) LatencySnapshot {
	var snap LatencySnapshot
	// Try for up to 100ms
	for i := 0; i < 50; i++ {
		snap = lt.Snapshot()
		if condition(snap) {
			return snap
		}
		time.Sleep(2 * time.Millisecond)
	}
	return snap
}

func TestNewLatencyTracker(t *testing.T) {
	lt := NewLatencyTracker()
	defer lt.Close()
	if lt == nil {
		t.Fatal("NewLatencyTracker returned nil")
	}
	if lt.histogram == nil {
		t.Error("Histogram not initialized")
	}
	if lt.count != 0 {
		t.Error("Initial count should be 0")
	}
	if lt.sum != 0 {
		t.Error("Initial sum should be 0")
	}
}

func TestRecord_Basic(t *testing.T) {
	lt := NewLatencyTracker()
	defer lt.Close()

	lt.Record(100)
	lt.Record(200)
	lt.Record(300)

	// Wait for count to match
	snap := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 3
	})

	if snap.Count != 3 {
		t.Errorf("Expected count 3, got %d", snap.Count)
	}
	if snap.Sum != 600 {
		t.Errorf("Expected sum 600, got %d", snap.Sum)
	}
	if snap.Avg != 200 {
		t.Errorf("Expected avg 200, got %d", snap.Avg)
	}
	if snap.P50 != 200 {
		t.Errorf("Expected P50 200, got %d", snap.P50)
	}
	if snap.Max != 300 {
		t.Errorf("Expected Max 300, got %d", snap.Max)
	}
}

func TestRecord_OutOfBounds(t *testing.T) {
	lt := NewLatencyTracker()
	defer lt.Close()

	// The HDR histogram with 3 significant figures creates buckets.
	// When we try to record 70,000,000 (above max 60,000,000),
	// it gets recorded in the max bucket.
	lt.Record(70000000)

	snap := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 1
	})

	// The HDR histogram creates buckets. With 3 significant figures:
	// Highest bucket value for range up to 60,000,000 is 60,030,975
	if snap.Max < 60000000 {
		t.Errorf("Max should be at least 60,000,000, got %d", snap.Max)
	}
	if snap.Max > 61000000 {
		t.Errorf("Max should be <= 61,000,000, got %d", snap.Max)
	}
	if snap.Sum < 60000000 {
		t.Errorf("Sum should be at least 60,000,000, got %d", snap.Sum)
	}
}

func TestRecord_ZeroCountAvg(t *testing.T) {
	lt := NewLatencyTracker()
	defer lt.Close()
	snap := lt.Snapshot()
	if snap.Avg != 0 {
		t.Errorf("Expected avg 0 on zero count, got %d", snap.Avg)
	}
}

func TestRotation(t *testing.T) {
	lt := NewLatencyTracker()
	defer lt.Close()

	// Record first value
	lt.Record(100)

	// Get initial snapshot
	snap1 := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 1
	})
	if snap1.Count != 1 {
		t.Errorf("Before rotation: expected count 1, got %d", snap1.Count)
	}

	// Manually force rotation by setting lastRotation far in the past
	lt.mu.Lock()
	lt.lastRotation = time.Now().Add(-woos.HistogramWindow - time.Second)
	lt.mu.Unlock()

	// This record should trigger auto-rotation
	lt.Record(200)

	// After rotation, only the new value should be in the histogram.
	// We wait until Max reflects the new value (200), ensuring the background
	// worker has written the value to the histogram after the reset.
	snap2 := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Max == 200
	})

	if snap2.Count != 1 {
		t.Errorf("After rotation: expected count 1, got %d", snap2.Count)
	}
	if snap2.Sum != 200 {
		t.Errorf("After rotation: expected sum 200, got %d", snap2.Sum)
	}
	if snap2.Max != 200 {
		t.Errorf("After rotation: expected Max 200, got %d", snap2.Max)
	}
}

func TestConcurrentRecord(t *testing.T) {
	lt := NewLatencyTracker()
	defer lt.Close()

	const goroutines = 10
	const recordsPerGoroutine = 1000
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < recordsPerGoroutine; i++ {
				lt.Record(int64(i + 1))
			}
		}()
	}

	wg.Wait()

	snap := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == uint64(goroutines*recordsPerGoroutine)
	})

	expected := goroutines * recordsPerGoroutine
	if snap.Count != uint64(expected) {
		t.Errorf("Expected count %d, got %d", expected, snap.Count)
	}
}

func TestSnapshot_Isolation(t *testing.T) {
	lt := NewLatencyTracker()
	defer lt.Close()

	lt.Record(100)
	snap1 := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 1
	})

	lt.Record(200)
	snap2 := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 2
	})

	if snap1.Count != 1 {
		t.Errorf("First snapshot should have count 1, got %d", snap1.Count)
	}
	if snap2.Count != 2 {
		t.Errorf("Second snapshot should have count 2, got %d", snap2.Count)
	}
	if snap1.Sum != 100 {
		t.Errorf("First snapshot should have sum 100, got %d", snap1.Sum)
	}
	if snap2.Sum != 300 {
		t.Errorf("Second snapshot should have sum 300, got %d", snap2.Sum)
	}
}

func TestHistogram_Accuracy(t *testing.T) {
	lt := NewLatencyTracker()
	defer lt.Close()

	// Record values that should give precise percentiles
	values := []int64{100, 200, 300, 400, 500, 600, 700, 800, 900, 1000}
	for _, v := range values {
		lt.Record(v)
	}

	snap := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 10
	})

	// With 10 evenly distributed values, percentiles should be predictable
	// Note: HDR histogram buckets values, so we need tolerance
	if snap.P50 < 400 || snap.P50 > 600 {
		t.Errorf("P50 should be around 500, got %d", snap.P50)
	}
	if snap.P90 < 800 || snap.P90 > 1000 {
		t.Errorf("P90 should be around 900, got %d", snap.P90)
	}
	if snap.P99 < 900 || snap.P99 > 1000 {
		t.Errorf("P99 should be around 990, got %d", snap.P99)
	}
}

func TestRecord_Negative(t *testing.T) {
	lt := NewLatencyTracker()
	defer lt.Close()

	// Negative values get recorded in the highest bucket (60,030,975)
	// because RecordValue fails check < MinUS and defaults to MaxUS
	lt.Record(-100)

	snap := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 1
	})

	if snap.Count != 1 {
		t.Errorf("Should record negative, count: %d", snap.Count)
	}
	// Negative values end up in the max bucket (60,030,975)
	if snap.Max < 60000000 || snap.Max > 61000000 {
		t.Errorf("Negative should be in max bucket (60M-61M), got %d", snap.Max)
	}
	if snap.Sum < 60000000 {
		t.Errorf("Negative sum should be >= 60,000,000, got %d", snap.Sum)
	}
}

func TestRecord_AllZero(t *testing.T) {
	lt := NewLatencyTracker()
	defer lt.Close()

	// Test with 0, 1, 2
	// 0 is < MinUS (1), so it gets mapped to MaxUS (60M) based on current logic
	lt.Record(0)
	lt.Record(1)
	lt.Record(2)

	snap := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 3
	})

	if snap.Count != 3 {
		t.Errorf("Expected count 3, got %d", snap.Count)
	}
	// Verify that 0 resulted in a large sum (indicating mapped to MaxUS)
	if snap.Sum < 60000000 {
		t.Errorf("Expected sum > 60M (0 mapped to max), got %d", snap.Sum)
	}
}

func TestRecord_SmallValues(t *testing.T) {
	lt := NewLatencyTracker()
	defer lt.Close()

	// Test very small values
	lt.Record(1)
	lt.Record(2)
	lt.Record(3)

	snap := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 3
	})

	if snap.Count != 3 {
		t.Errorf("Expected count 3, got %d", snap.Count)
	}
	if snap.Sum != 6 {
		t.Errorf("Expected sum 6, got %d", snap.Sum)
	}
	if snap.Max != 3 {
		t.Errorf("Expected Max 3, got %d", snap.Max)
	}
}

func TestRecord_MixedValues(t *testing.T) {
	lt := NewLatencyTracker()
	defer lt.Close()

	// Mix of valid, negative, and out-of-bounds values
	lt.Record(100)      // valid
	lt.Record(-50)      // negative -> max bucket
	lt.Record(50000000) // valid, but large
	lt.Record(70000000) // out of bounds -> max bucket

	snap := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 4
	})

	if snap.Count != 4 {
		t.Errorf("Expected count 4, got %d", snap.Count)
	}
	// At least 3 values contributed to sum (100 + 50000000 + 2*maxBucket)
	if snap.Sum < 50100100 {
		t.Errorf("Sum too small, got %d", snap.Sum)
	}
}

func TestRecord_ZeroValue(t *testing.T) {
	lt := NewLatencyTracker()
	defer lt.Close()

	// Test what happens with 0
	lt.Record(0)

	snap := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 1
	})

	if snap.Count != 1 {
		t.Errorf("Should record 0, count: %d", snap.Count)
	}
	// 0 maps to MaxUS
	if snap.Max < 60000000 {
		t.Errorf("0 should map to max bucket, got %d", snap.Max)
	}
}
