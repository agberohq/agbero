package metrics

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
)

const HistogramWindow = 60 * time.Second

const (
	minUS = int64(1)
	maxUS = int64(60_000_000)
)

type LatencyTracker struct {
	mu           sync.Mutex
	histogram    *hdrhistogram.Histogram
	lastRotation time.Time

	count   uint64
	sum     int64
	dropped uint64

	ch   chan int64
	stop chan struct{}
	wg   sync.WaitGroup
}

func NewLatencyTracker() *LatencyTracker {
	lt := &LatencyTracker{
		histogram:    hdrhistogram.New(minUS, maxUS, 3),
		lastRotation: time.Now(),
		ch:           make(chan int64, 8192),
		stop:         make(chan struct{}),
	}
	lt.wg.Add(1)
	go lt.run()
	return lt
}

func (lt *LatencyTracker) Close() {
	select {
	case <-lt.stop:
		return
	default:
		close(lt.stop)
	}
	lt.wg.Wait()
}

func (lt *LatencyTracker) Record(microseconds int64) {
	now := time.Now()

	lt.mu.Lock()
	lt.rotateLocked(now)
	lt.mu.Unlock()

	v := microseconds
	if v < minUS || v > maxUS {
		v = maxUS
	}

	atomic.AddUint64(&lt.count, 1)
	atomic.AddInt64(&lt.sum, v)

	select {
	case lt.ch <- v:
	default:
		atomic.AddUint64(&lt.dropped, 1)
	}
}

type LatencySnapshot struct {
	P50   int64  `json:"p50"`
	P90   int64  `json:"p90"`
	P99   int64  `json:"p99"`
	Max   int64  `json:"max"`
	Count uint64 `json:"count"`
	Sum   int64  `json:"sum_us"`
	Avg   int64  `json:"avg_us"`

	Dropped uint64 `json:"dropped,omitempty"`
}

func (lt *LatencyTracker) Snapshot() LatencySnapshot {
	now := time.Now()

	lt.mu.Lock()
	lt.flushLocked()
	lt.rotateLocked(now)

	snap := LatencySnapshot{
		P50: lt.histogram.ValueAtQuantile(50),
		P90: lt.histogram.ValueAtQuantile(90),
		P99: lt.histogram.ValueAtQuantile(99),
		Max: lt.histogram.Max(),
	}
	lt.mu.Unlock()

	snap.Count = atomic.LoadUint64(&lt.count)
	snap.Sum = atomic.LoadInt64(&lt.sum)
	snap.Dropped = atomic.LoadUint64(&lt.dropped)

	if snap.Count > 0 {
		snap.Avg = snap.Sum / int64(snap.Count)
	}

	return snap
}

func (lt *LatencyTracker) run() {
	defer lt.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-lt.stop:
			return

		case us := <-lt.ch:
			lt.mu.Lock()
			_ = lt.histogram.RecordValue(us)
			lt.mu.Unlock()

		case <-ticker.C:
			lt.mu.Lock()
			lt.rotateLocked(time.Now())
			lt.mu.Unlock()
		}
	}
}

func (lt *LatencyTracker) flushLocked() {
	for {
		select {
		case us := <-lt.ch:
			_ = lt.histogram.RecordValue(us)
		default:
			return
		}
	}
}

func (lt *LatencyTracker) rotateLocked(now time.Time) {
	if now.Sub(lt.lastRotation) <= HistogramWindow {
		return
	}

	lt.flushLocked()

	lt.histogram.Reset()
	lt.lastRotation = now

	atomic.StoreUint64(&lt.count, 0)
	atomic.StoreInt64(&lt.sum, 0)
	atomic.StoreUint64(&lt.dropped, 0)
}
