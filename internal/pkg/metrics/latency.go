package metrics

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
	"github.com/agberohq/agbero/internal/core/woos"
)

var snapshotHistogramPool = sync.Pool{
	New: func() any {
		return hdrhistogram.New(woos.MinUS, woos.MaxUS, 3)
	},
}

type shard struct {
	mu           sync.Mutex
	histogram    *hdrhistogram.Histogram
	count        uint64
	sum          int64
	lastRotation int64    // guarded by mu — no global atomic needed
	_            [40]byte // prevent false sharing
}

type Latency struct {
	shards    []shard
	numShards uint64
	nextShard atomic.Uint64
	closed    atomic.Bool
}

func NewLatency() *Latency {
	n := max(runtime.GOMAXPROCS(0)*2, 16)

	now := time.Now().UnixNano()
	lt := &Latency{
		shards:    make([]shard, n),
		numShards: uint64(n),
	}

	for i := range lt.shards {
		lt.shards[i].histogram = hdrhistogram.New(woos.MinUS, woos.MaxUS, 3)
		lt.shards[i].lastRotation = now
	}

	return lt
}

func (lt *Latency) Close() {
	lt.closed.Store(true)
}

func (lt *Latency) Record(microseconds int64) {
	if lt.closed.Load() {
		return
	}

	v := microseconds
	if v < woos.MinUS || v > woos.MaxUS {
		v = woos.MaxUS
	}

	s := &lt.shards[lt.nextShard.Add(1)%lt.numShards]

	s.mu.Lock()
	now := time.Now().UnixNano()
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
		P50:   merged.ValueAtQuantile(50),
		P90:   merged.ValueAtQuantile(90),
		P99:   merged.ValueAtQuantile(99),
		Max:   merged.Max(),
		Count: totalCount,
		Sum:   totalSum,
	}
	if totalCount > 0 {
		snap.Avg = totalSum / int64(totalCount)
	}

	return snap
}
