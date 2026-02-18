package metrics

import (
	"sync"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
)

func getSnapshotEventually(lt *Latency, condition func(s LatencySnapshot) bool) LatencySnapshot {
	var snap LatencySnapshot
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
	lt := NewLatency()
	defer lt.Close()

	if lt == nil {
		t.Fatal("NewLatency returned nil")
	}
	if lt.histogram == nil {
		t.Error("Histogram not initialized")
	}
	if lt.sum.Load() != 0 {
		t.Errorf("Initial sum should be 0, got %d", lt.sum.Load())
	}
	if lt.dropped.Load() != 0 {
		t.Errorf("Initial dropped should be 0, got %d", lt.dropped.Load())
	}
	if lt.lastRotation.Load() == 0 {
		t.Error("lastRotation should be set to current time")
	}
}

func TestRecord_Basic(t *testing.T) {
	lt := NewLatency()
	defer lt.Close()

	lt.Record(100)
	lt.Record(200)
	lt.Record(300)

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
	lt := NewLatency()
	defer lt.Close()

	lt.Record(70000000)

	snap := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 1
	})

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
	lt := NewLatency()
	defer lt.Close()
	snap := lt.Snapshot()
	if snap.Avg != 0 {
		t.Errorf("Expected avg 0 on zero count, got %d", snap.Avg)
	}
}

func TestRotation(t *testing.T) {
	lt := NewLatency()
	defer lt.Close()

	lt.Record(100)
	snap1 := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 1
	})
	if snap1.Count != 1 {
		t.Errorf("Before rotation: expected count 1, got %d", snap1.Count)
	}

	lt.lastRotation.Store(time.Now().Add(-woos.HistogramWindow - time.Second).UnixNano())
	lt.Record(200)

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
	lt := NewLatency()
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
	lt := NewLatency()
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
	lt := NewLatency()
	defer lt.Close()

	values := []int64{100, 200, 300, 400, 500, 600, 700, 800, 900, 1000}
	for _, v := range values {
		lt.Record(v)
	}

	snap := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 10
	})

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
	lt := NewLatency()
	defer lt.Close()

	lt.Record(-100)

	snap := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 1
	})

	if snap.Count != 1 {
		t.Errorf("Should record negative, count: %d", snap.Count)
	}
	// Defensive: negative values penalized as worst case
	if snap.Max < 60000000 || snap.Max > 61000000 {
		t.Errorf("Negative should be in max bucket (60M-61M), got %d", snap.Max)
	}
	if snap.Sum < 60000000 {
		t.Errorf("Negative sum should be >= 60,000,000, got %d", snap.Sum)
	}
}

func TestRecord_AllZero(t *testing.T) {
	lt := NewLatency()
	defer lt.Close()

	lt.Record(0)
	lt.Record(1)
	lt.Record(2)

	snap := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 3
	})

	if snap.Count != 3 {
		t.Errorf("Expected count 3, got %d", snap.Count)
	}
	// 0 is penalized as worst case, 1 and 2 are valid
	expectedSum := int64(woos.MaxUS + 1 + 2)
	if snap.Sum != expectedSum {
		t.Errorf("Expected sum %d (0->max + 1 + 2), got %d", expectedSum, snap.Sum)
	}
}

func TestRecord_SmallValues(t *testing.T) {
	lt := NewLatency()
	defer lt.Close()

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
	lt := NewLatency()
	defer lt.Close()

	lt.Record(100)
	lt.Record(-50)
	lt.Record(50000000)
	lt.Record(70000000)

	snap := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 4
	})

	if snap.Count != 4 {
		t.Errorf("Expected count 4, got %d", snap.Count)
	}
	// -50 and 70000000 both map to max bucket
	expectedMinSum := int64(100 + 50000000 + 2*woos.MaxUS)
	if snap.Sum < expectedMinSum {
		t.Errorf("Sum too small, expected >= %d, got %d", expectedMinSum, snap.Sum)
	}
}

func TestRecord_ZeroValue(t *testing.T) {
	lt := NewLatency()
	defer lt.Close()

	lt.Record(0)

	snap := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 1
	})

	if snap.Count != 1 {
		t.Errorf("Should record 0, count: %d", snap.Count)
	}
	// Defensive: 0 penalized as worst case
	if snap.Max < 60000000 {
		t.Errorf("0 should map to max bucket, got %d", snap.Max)
	}
}

func TestRecord_AfterClose(t *testing.T) {
	lt := NewLatency()
	lt.Close()

	lt.Record(100)

	snap := lt.Snapshot()
	if snap.Count != 0 {
		t.Errorf("Should not record after close, got count %d", snap.Count)
	}
}

func TestRecord_MinBoundary(t *testing.T) {
	lt := NewLatency()
	defer lt.Close()

	lt.Record(woos.MinUS)

	snap := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 1
	})

	if snap.Max != woos.MinUS {
		t.Errorf("MinUS should record exactly, got %d", snap.Max)
	}
	if snap.Sum != int64(woos.MinUS) {
		t.Errorf("Sum should be MinUS, got %d", snap.Sum)
	}
}

func TestRecord_MaxBoundary(t *testing.T) {
	lt := NewLatency()
	defer lt.Close()

	lt.Record(woos.MaxUS)

	snap := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 1
	})

	if snap.Max < woos.MaxUS {
		t.Errorf("MaxUS should record at least MaxUS, got %d", snap.Max)
	}
	if snap.Sum < woos.MaxUS {
		t.Errorf("Sum should be >= MaxUS, got %d", snap.Sum)
	}
}
