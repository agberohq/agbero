package metrics

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
	"github.com/agberohq/agbero/internal/core/woos"
)

type Latency struct {
	mu           sync.Mutex
	histogram    *hdrhistogram.Histogram
	lastRotation atomic.Int64
	sum          atomic.Int64
	dropped      atomic.Uint64
	closed       atomic.Bool
}

func NewLatency() *Latency {
	lt := &Latency{
		histogram: hdrhistogram.New(woos.MinUS, woos.MaxUS, 3),
	}
	lt.lastRotation.Store(time.Now().UnixNano())
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
	// Defensive clamping: invalid values penalized as worst case
	if v < woos.MinUS || v > woos.MaxUS {
		v = woos.MaxUS
	}

	now := time.Now()

	lt.mu.Lock()
	defer lt.mu.Unlock()

	// Check rotation
	last := time.Unix(0, lt.lastRotation.Load())
	if now.Sub(last) > woos.HistogramWindow {
		lt.histogram.Reset()
		lt.lastRotation.Store(now.UnixNano())
		lt.sum.Store(0)
	}

	lt.histogram.RecordValue(v)
	lt.sum.Add(v)
}

type LatencySnapshot struct {
	P50     int64  `json:"p50"`
	P90     int64  `json:"p90"`
	P99     int64  `json:"p99"`
	Max     int64  `json:"max"`
	Count   uint64 `json:"count"`
	Sum     int64  `json:"sum_us"`
	Avg     int64  `json:"avg_us"`
	Dropped uint64 `json:"dropped,omitempty"`
}

func (lt *Latency) Snapshot() LatencySnapshot {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	snap := LatencySnapshot{
		P50:   lt.histogram.ValueAtQuantile(50),
		P90:   lt.histogram.ValueAtQuantile(90),
		P99:   lt.histogram.ValueAtQuantile(99),
		Max:   lt.histogram.Max(),
		Count: uint64(lt.histogram.TotalCount()),
	}

	snap.Sum = lt.sum.Load()
	snap.Dropped = lt.dropped.Load()
	if snap.Count > 0 {
		snap.Avg = snap.Sum / int64(snap.Count)
	}

	return snap
}
