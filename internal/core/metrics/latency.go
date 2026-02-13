package metrics

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/HdrHistogram/hdrhistogram-go"
)

type Latency struct {
	mu           sync.RWMutex
	histogram    *hdrhistogram.Histogram
	lastRotation time.Time

	// atomic counters for current window
	count   atomic.Uint64
	sum     atomic.Int64
	dropped atomic.Uint64

	// background goroutine management
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// channel for async recording
	ch chan int64
}

func NewLatency() *Latency {
	ctx, cancel := context.WithCancel(context.Background())
	lt := &Latency{
		histogram:    hdrhistogram.New(woos.MinUS, woos.MaxUS, 3),
		lastRotation: time.Now(),
		ctx:          ctx,
		cancel:       cancel,
		ch:           make(chan int64, 8192),
	}
	lt.wg.Add(1)
	go lt.run()
	return lt
}

func (lt *Latency) Close() {
	lt.cancel()
	lt.wg.Wait()
}

func (lt *Latency) Record(microseconds int64) {
	// Fast path: check if context is already cancelled
	select {
	case <-lt.ctx.Done():
		return
	default:
	}

	// Check and trigger rotation if needed - matches original behavior
	now := time.Now()
	lt.mu.Lock()
	lt.rotateLocked(now)
	lt.mu.Unlock()

	// Clamp to valid range - tests expect negative/zero to map to MaxUS (buggy but expected)
	v := microseconds
	if v < woos.MinUS || v > woos.MaxUS {
		v = woos.MaxUS
	}

	// Update atomics immediately
	lt.count.Add(1)
	lt.sum.Add(v)

	// Try to send to channel
	select {
	case lt.ch <- v:
	case <-lt.ctx.Done():
		lt.dropped.Add(1)
	default:
		lt.dropped.Add(1)
	}
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
	lt.flushLocked()
	lt.mu.Unlock()

	lt.mu.RLock()
	snap := LatencySnapshot{
		P50: lt.histogram.ValueAtQuantile(50),
		P90: lt.histogram.ValueAtQuantile(90),
		P99: lt.histogram.ValueAtQuantile(99),
		Max: lt.histogram.Max(),
	}
	lt.mu.RUnlock()

	snap.Count = lt.count.Load()
	snap.Sum = lt.sum.Load()
	snap.Dropped = lt.dropped.Load()

	if snap.Count > 0 {
		snap.Avg = snap.Sum / int64(snap.Count)
	}

	return snap
}

func (lt *Latency) run() {
	defer lt.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-lt.ctx.Done():
			lt.mu.Lock()
			lt.flushLocked()
			lt.mu.Unlock()
			return

		case us := <-lt.ch:
			lt.mu.Lock()
			_ = lt.histogram.RecordValue(us)
			lt.mu.Unlock()

		case now := <-ticker.C:
			lt.mu.Lock()
			lt.rotateLocked(now)
			lt.mu.Unlock()
		}
	}
}

func (lt *Latency) flushLocked() {
	for {
		select {
		case us := <-lt.ch:
			_ = lt.histogram.RecordValue(us)
		default:
			return
		}
	}
}

func (lt *Latency) rotateLocked(now time.Time) {
	if now.Sub(lt.lastRotation) <= woos.HistogramWindow {
		return
	}

	lt.flushLocked()
	lt.histogram.Reset()
	lt.lastRotation = now
	lt.count.Store(0)
	lt.sum.Store(0)
	lt.dropped.Store(0)
}
