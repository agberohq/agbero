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
)

var snapshotHistogramPool = sync.Pool{
	New: func() any {
		return hdrhistogram.New(woos.MinUS, woos.MaxUS, sigFigPrecision)
	},
}

type shard struct {
	mu           sync.Mutex
	histogram    *hdrhistogram.Histogram
	count        uint64
	sum          int64
	lastRotation int64
	_            [cacheLinePadding]byte
}

type Latency struct {
	shards    []shard
	numShards uint64
	nextShard atomic.Uint64
	closed    atomic.Bool
}

// nextPowerOfTwo calculates the nearest power of two for an integer
// Enables rapid bitwise modulo operations on hot paths
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

// NewLatency initializes a sharded histogram structure for metric tracking
// Rounds the number of shards to a power of two to optimize indexing math
func NewLatency() *Latency {
	cpuCores := uint64(runtime.GOMAXPROCS(0) * cpuMultiplier)
	n := max(cpuCores, minLatencyShards)
	optimalShards := nextPowerOfTwo(n)

	now := time.Now().UnixNano()
	lt := &Latency{
		shards:    make([]shard, optimalShards),
		numShards: optimalShards,
	}

	for i := range lt.shards {
		lt.shards[i].histogram = hdrhistogram.New(woos.MinUS, woos.MaxUS, sigFigPrecision)
		lt.shards[i].lastRotation = now
	}

	return lt
}

// Close permanently stops new latency metrics from being recorded
// Flips the atomic closed flag to bypass incoming telemetry payloads
func (lt *Latency) Close() {
	lt.closed.Store(true)
}

// Record injects a single latency measurement into the partitioned histogram
// Uses bitwise AND against a power-of-two mask instead of expensive division
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
	if now-s.lastRotation > int64(woos.HistogramWindow) {
		s.histogram.Reset()
		s.count = emptyCount
		s.sum = emptySum
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

// Snapshot generates a unified representation of all distributed latency shards
// Retrieves an empty histogram from the sync pool to reduce garbage collection load
func (lt *Latency) Snapshot() LatencySnapshot {
	merged := snapshotHistogramPool.Get().(*hdrhistogram.Histogram)
	merged.Reset()
	defer snapshotHistogramPool.Put(merged)

	var totalCount uint64
	var totalSum int64

	for i := range lt.shards {
		s := &lt.shards[i]
		s.mu.Lock()
		merged.Merge(s.histogram)
		totalCount += s.count
		totalSum += s.sum
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
