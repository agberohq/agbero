package metrics

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
	"github.com/agberohq/agbero/internal/core/woos"
)

const (
	minLatencyShards = 16
	cpuMultiplier    = 2
	percentile50     = 50
	percentile90     = 90
	percentile99     = 99
	emptyCount       = 0
	emptySum         = 0
	cacheLinePadding = 40
	sigFigPrecision  = 3
	shardIdleTimeout = 5 * time.Minute // Evict histogram after idle period
	evictionInterval = 1 * time.Minute // How often to check for idle shards
)

var snapshotHistogramPool = sync.Pool{
	New: func() any {
		return hdrhistogram.New(woos.MinUS, woos.MaxUS, sigFigPrecision)
	},
}

// lazyShard holds histogram data that may not exist yet (nil = not allocated)
type lazyShard struct {
	mu           sync.Mutex
	histogram    *hdrhistogram.Histogram // nil until first Record
	count        uint64
	sum          int64
	lastAccess   int64 // UnixNano for idle detection
	lastRotation int64
	_            [cacheLinePadding - 16]byte // Adjust padding for new fields
}

type Latency struct {
	shards       []lazyShard
	numShards    uint64
	nextShard    atomic.Uint64
	closed       atomic.Bool
	evictionStop chan struct{}
	evictionWg   sync.WaitGroup
}

// nextPowerOfTwo rounds v up to nearest power of two for fast modulo via bitmask
func nextPowerOfTwo(v uint64) uint64 {
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v |= v >> 32
	v++
	return v
}

// NewLatency creates a sharded histogram with lazy allocation.
// Shards start as nil histograms; memory only consumed on actual traffic.
func NewLatency() *Latency {
	cpuCores := uint64(runtime.GOMAXPROCS(0) * cpuMultiplier)
	n := max(cpuCores, minLatencyShards)
	optimalShards := nextPowerOfTwo(n)

	lt := &Latency{
		shards:       make([]lazyShard, optimalShards),
		numShards:    optimalShards,
		evictionStop: make(chan struct{}),
	}

	// Start background eviction goroutine
	lt.evictionWg.Add(1)
	go lt.evictionLoop()

	return lt
}

// Close shuts down the latency tracker and stops background eviction
func (lt *Latency) Close() {
	if lt.closed.CompareAndSwap(false, true) {
		close(lt.evictionStop)
		lt.evictionWg.Wait()
	}
}

// evictionLoop periodically reclaims memory from idle shards
func (lt *Latency) evictionLoop() {
	defer lt.evictionWg.Done()
	ticker := time.NewTicker(evictionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			lt.evictIdle()
		case <-lt.evictionStop:
			return
		}
	}
}

// evictIdle releases histogram memory from shards unused for shardIdleTimeout
func (lt *Latency) evictIdle() {
	cutoff := time.Now().Add(-shardIdleTimeout).UnixNano()

	for i := range lt.shards {
		s := &lt.shards[i]
		s.mu.Lock()
		if s.histogram != nil && s.lastAccess < cutoff {
			// Let GC collect - don't pool large histograms
			s.histogram = nil
			s.count = 0
			s.sum = 0
		}
		s.mu.Unlock()
	}
}

// Record adds a latency sample, allocating histogram on first use per shard.
// Rotates histograms on time windows; creates histograms lazily.
func (lt *Latency) Record(microseconds int64) {
	if lt.closed.Load() {
		return
	}

	v := microseconds
	if v < woos.MinUS || v > woos.MaxUS {
		v = woos.MaxUS
	}

	shardMask := lt.numShards - 1
	shardIndex := lt.nextShard.Add(1) & shardMask
	s := &lt.shards[shardIndex]

	s.mu.Lock()
	now := time.Now().UnixNano()
	s.lastAccess = now

	// Lazy allocation: create histogram only on first Record to this shard
	if s.histogram == nil {
		s.histogram = hdrhistogram.New(woos.MinUS, woos.MaxUS, sigFigPrecision)
		s.lastRotation = now
	}

	// Time-based rotation for fresh histogram windows
	if now-s.lastRotation > int64(woos.HistogramWindow) {
		s.histogram.Reset()
		s.count = 0
		s.sum = 0
		s.lastRotation = now
	}

	s.histogram.RecordValue(v)
	s.count++
	s.sum += v
	s.mu.Unlock()
}

type LatencySnapshot struct {
	P50   int64  `json:"p50"`
	P90   int64  `json:"p90"`
	P99   int64  `json:"p99"`
	Max   int64  `json:"max"`
	Count uint64 `json:"count"`
	Sum   int64  `json:"sum_us"`
	Avg   int64  `json:"avg_us"`
}

// Snapshot aggregates all active shards into a unified latency view.
// Skips unallocated (idle) shards efficiently.
func (lt *Latency) Snapshot() LatencySnapshot {
	merged := snapshotHistogramPool.Get().(*hdrhistogram.Histogram)
	merged.Reset()
	defer snapshotHistogramPool.Put(merged)

	var totalCount uint64
	var totalSum int64

	for i := range lt.shards {
		s := &lt.shards[i]
		s.mu.Lock()
		// Skip unallocated shards (no memory allocated, no traffic seen)
		if s.histogram != nil {
			merged.Merge(s.histogram)
			totalCount += s.count
			totalSum += s.sum
		}
		s.mu.Unlock()
	}

	snap := LatencySnapshot{
		P50:   merged.ValueAtQuantile(percentile50),
		P90:   merged.ValueAtQuantile(percentile90),
		P99:   merged.ValueAtQuantile(percentile99),
		Max:   merged.Max(),
		Count: totalCount,
		Sum:   totalSum,
	}
	if totalCount > emptyCount {
		snap.Avg = totalSum / int64(totalCount)
	}

	return snap
}
