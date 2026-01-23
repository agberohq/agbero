package metrics

import (
	"sync"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
)

// HistogramWindow defines how long we keep data before resetting.
const HistogramWindow = 60 * time.Second

type LatencyTracker struct {
	mu           sync.Mutex
	histogram    *hdrhistogram.Histogram
	lastRotation time.Time
	count        uint64 // Number of recorded samples
	sum          int64  // Total latency in microseconds
}

func NewLatencyTracker() *LatencyTracker {
	// Track 1 microsecond to 1 minute (60,000,000 µs)
	// 3 significant figures means highly accurate P99s.
	h := hdrhistogram.New(1, 60000000, 3)
	return &LatencyTracker{
		histogram:    h,
		lastRotation: time.Now(),
	}
}

func (lt *LatencyTracker) Record(microseconds int64) {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	// Auto-rotation logic
	if time.Since(lt.lastRotation) > HistogramWindow {
		lt.histogram.Reset()
		lt.count = 0
		lt.sum = 0
		lt.lastRotation = time.Now()
	}

	if err := lt.histogram.RecordValue(microseconds); err != nil {
		// Cap at max tracking value if out of bounds
		_ = lt.histogram.RecordValue(60000000)
		microseconds = 60000000 // Adjust for sum
	}

	lt.count++
	lt.sum += microseconds
}

type LatencySnapshot struct {
	P50   int64  `json:"p50"`
	P90   int64  `json:"p90"`
	P99   int64  `json:"p99"`
	Max   int64  `json:"max"`
	Count uint64 `json:"count"`  // Total requests/samples
	Sum   int64  `json:"sum_us"` // Total latency in microseconds
	Avg   int64  `json:"avg_us"` // Average latency (derived)
}

func (lt *LatencyTracker) Snapshot() LatencySnapshot {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	snap := LatencySnapshot{
		P50:   lt.histogram.ValueAtQuantile(50),
		P90:   lt.histogram.ValueAtQuantile(90),
		P99:   lt.histogram.ValueAtQuantile(99),
		Max:   lt.histogram.Max(),
		Count: lt.count,
		Sum:   lt.sum,
	}

	if snap.Count > 0 {
		snap.Avg = snap.Sum / int64(snap.Count)
	}

	return snap
}
