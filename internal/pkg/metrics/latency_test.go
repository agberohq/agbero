package metrics

import (
	"sync"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/woos"
)

func getSnapshotEventually(lt *Latency, condition func(s LatencySnapshot) bool) LatencySnapshot {
	var snap LatencySnapshot
	for range 50 {
		snap = lt.Snapshot()
		if condition(snap) {
			return snap
		}
		time.Sleep(2 * time.Millisecond)
	}
	return snap
}

func TestNewLatency(t *testing.T) {
	lt := NewLatency()
	defer lt.Close()

	if lt == nil {
		t.Fatal("NewLatency returned nil")
	}
	if lt.numShards == 0 {
		t.Error("numShards should be set")
	}
	if len(lt.shards) == 0 {
		t.Error("shards should be allocated")
	}
	// Verify lazy allocation - all histograms should start nil
	for i, s := range lt.shards {
		if s.histogram != nil {
			t.Errorf("Shard %d should start with nil histogram", i)
		}
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

	if snap.Count != 1 {
		t.Errorf("Expected count 1, got %d", snap.Count)
	}
	// Out of bounds gets clamped to MaxUS
	if snap.Max < woos.MaxUS {
		t.Errorf("Max should be at least %d, got %d", woos.MaxUS, snap.Max)
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

	// Record to a specific shard and track it
	shardMask := lt.numShards - 1
	targetShard := (lt.nextShard.Add(1) & shardMask)
	lt.Record(100)

	// Verify first record landed
	snap1 := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count >= 1
	})
	if snap1.Count < 1 {
		t.Fatalf("Before rotation: expected at least count 1, got %d", snap1.Count)
	}

	// Force rotation on the specific shard we wrote to
	lt.shards[targetShard].mu.Lock()
	lt.shards[targetShard].lastRotation = time.Now().Add(-woos.HistogramWindow - time.Second).UnixNano()
	lt.shards[targetShard].mu.Unlock()

	// Record again - should trigger rotation on that shard
	// Use same shard index by manipulating nextShard
	lt.nextShard.Store(targetShard - 1) // Subtract 1 because Record will Add(1)
	lt.Record(200)

	// Wait for the new record to be visible
	getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count >= 1
	})

	// Check the rotated shard specifically
	lt.shards[targetShard].mu.Lock()
	rotatedCount := lt.shards[targetShard].count
	rotatedSum := lt.shards[targetShard].sum
	lt.shards[targetShard].mu.Unlock()

	if rotatedCount != 1 {
		t.Errorf("After rotation: expected rotated shard count 1, got %d", rotatedCount)
	}
	if rotatedSum != 200 {
		t.Errorf("After rotation: expected rotated shard sum 200, got %d", rotatedSum)
	}
}

func TestConcurrentRecord(t *testing.T) {
	lt := NewLatency()
	defer lt.Close()

	const goroutines = 10
	const recordsPerGoroutine = 1000
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			for i := range recordsPerGoroutine {
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
	// Negative values are clamped to MinUS (1)
	if snap.Max < woos.MinUS {
		t.Errorf("Negative should be clamped to MinUS (%d), got %d", woos.MinUS, snap.Max)
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

func TestLazyAllocation(t *testing.T) {
	lt := NewLatency()
	defer lt.Close()

	// Before any records, histograms should be nil
	activeShards := 0
	for _, s := range lt.shards {
		s.mu.Lock()
		if s.histogram != nil {
			activeShards++
		}
		s.mu.Unlock()
	}
	if activeShards != 0 {
		t.Errorf("Expected 0 active shards initially, got %d", activeShards)
	}

	// Record once - should allocate exactly one shard
	lt.Record(100)

	// Check that at least one shard is now allocated
	activeShards = 0
	for _, s := range lt.shards {
		s.mu.Lock()
		if s.histogram != nil {
			activeShards++
		}
		s.mu.Unlock()
	}
	if activeShards == 0 {
		t.Error("Expected at least 1 active shard after recording")
	}
}

func TestEviction(t *testing.T) {
	lt := NewLatency()
	defer lt.Close()

	// Record to allocate a histogram
	lt.Record(100)
	snap1 := getSnapshotEventually(lt, func(s LatencySnapshot) bool {
		return s.Count == 1
	})
	if snap1.Count != 1 {
		t.Fatalf("Expected count 1, got %d", snap1.Count)
	}

	// Manually set lastAccess to trigger eviction
	lt.shards[0].mu.Lock()
	lt.shards[0].lastAccess = time.Now().Add(-10 * time.Minute).UnixNano()
	lt.shards[0].mu.Unlock()

	// Trigger eviction
	lt.evictIdle()

	// Verify histogram was evicted
	lt.shards[0].mu.Lock()
	evicted := lt.shards[0].histogram == nil
	lt.shards[0].mu.Unlock()

	if !evicted {
		t.Error("Expected histogram to be evicted after idle timeout")
	}
}

// BenchmarkAllocation shows memory allocation behavior for lazy vs eager allocation
func BenchmarkAllocation(b *testing.B) {
	b.Run("Lazy_FreshBackend", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			lt := NewLatency()
			// Don't record - simulate idle backend
			lt.Close()
		}
	})

	b.Run("Lazy_SingleRecord", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			lt := NewLatency()
			lt.Record(100) // Allocates one histogram
			lt.Close()
		}
	})

	b.Run("Lazy_FullShards", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			lt := NewLatency()
			// Fill all shards to show worst-case allocation
			for j := 0; j < 32; j++ {
				lt.Record(int64(100 + j))
			}
			lt.Close()
		}
	})

	b.Run("Snapshot_Empty", func(b *testing.B) {
		lt := NewLatency()
		defer lt.Close()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = lt.Snapshot()
		}
	})

	b.Run("Snapshot_Active", func(b *testing.B) {
		lt := NewLatency()
		defer lt.Close()
		// Pre-fill with data
		for i := 0; i < 1000; i++ {
			lt.Record(int64(100 + i%900))
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = lt.Snapshot()
		}
	})
}

// BenchmarkMemoryGrowth tracks actual memory usage per backend
func BenchmarkMemoryGrowth(b *testing.B) {
	// Simulate the scale scenario: many backends, varying activity levels

	b.Run("IdleBackends", func(b *testing.B) {
		backends := make([]*Latency, 100)
		for i := range backends {
			backends[i] = NewLatency()
		}

		b.ReportAllocs()
		b.ResetTimer()

		// Just close them - measure baseline overhead
		for _, lt := range backends {
			lt.Close()
		}
	})

	b.Run("LightTraffic_10Percent", func(b *testing.B) {
		backends := make([]*Latency, 100)
		for i := range backends {
			backends[i] = NewLatency()
		}

		// 10% of backends get traffic, 1-2 records each
		for i := 0; i < 10; i++ {
			backends[i].Record(100)
		}

		b.ReportAllocs()
		b.ResetTimer()

		for _, lt := range backends {
			lt.Close()
		}
	})

	b.Run("HeavyTraffic_AllShards", func(b *testing.B) {
		backends := make([]*Latency, 100)
		for i := range backends {
			backends[i] = NewLatency()
		}

		// All backends, fill all shards
		for _, lt := range backends {
			for j := 0; j < 32; j++ {
				lt.Record(int64(100 + j))
			}
		}

		b.ReportAllocs()
		b.ResetTimer()

		for _, lt := range backends {
			lt.Close()
		}
	})
}
