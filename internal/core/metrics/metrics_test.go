package metrics

import (
	"testing"
	"time"
)

func TestNewLatencyTracker(t *testing.T) {
	lt := NewLatencyTracker()
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

	lt.Record(100)
	lt.Record(200)
	lt.Record(300)

	snap := lt.Snapshot()
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

	lt.Record(70000000) // > max (60e6), should cap at 60e6

	snap := lt.Snapshot()
	if snap.Max != 60000000 {
		t.Errorf("Expected capped Max 60000000, got %d", snap.Max)
	}
	if snap.Sum != 60000000 {
		t.Errorf("Expected capped sum 60000000, got %d", snap.Sum)
	}
}

func TestRecord_ZeroCountAvg(t *testing.T) {
	lt := NewLatencyTracker()
	snap := lt.Snapshot()
	if snap.Avg != 0 {
		t.Errorf("Expected avg 0 on zero count, got %d", snap.Avg)
	}
}

func TestRotation(t *testing.T) {
	lt := NewLatencyTracker()

	lt.Record(100)
	time.Sleep(61 * time.Second) // > HistogramWindow

	lt.Record(200)

	snap := lt.Snapshot()
	if snap.Count != 1 {
		t.Errorf("Expected count 1 after rotation, got %d", snap.Count)
	}
	if snap.Sum != 200 {
		t.Errorf("Expected sum 200 after rotation, got %d", snap.Sum)
	}
	if snap.Max != 200 {
		t.Errorf("Expected Max 200 after rotation, got %d", snap.Max)
	}
}

func TestConcurrentRecord(t *testing.T) {
	lt := NewLatencyTracker()
	done := make(chan struct{})

	go func() {
		for i := 0; i < 1000; i++ {
			lt.Record(int64(i + 1))
		}
		close(done)
	}()

	for i := 0; i < 1000; i++ {
		lt.Record(int64(i + 1001))
	}

	<-done

	snap := lt.Snapshot()
	if snap.Count != 2000 {
		t.Errorf("Expected count 2000, got %d", snap.Count)
	}
}
