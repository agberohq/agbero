package main

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HdrHistogram/hdrhistogram-go"
)

type Histogram struct {
	mu     sync.RWMutex
	hdr    *hdrhistogram.Histogram
	values []time.Duration // Keep for fallback/custom percentiles
	useHDR bool
}

func NewHistogram(useHDR bool) *Histogram {
	if useHDR {
		// 1 microsecond to 1 hour, 3 significant digits
		hdr := hdrhistogram.New(1, 3600000000, 3)
		return &Histogram{hdr: hdr, useHDR: true}
	}
	return &Histogram{values: make([]time.Duration, 0, 1000), useHDR: false}
}

func (h *Histogram) Record(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.useHDR {
		h.hdr.RecordValue(d.Microseconds())
	} else {
		h.values = append(h.values, d)
		if len(h.values) > 10000 {
			h.values = h.values[len(h.values)-5000:]
		}
	}
}

func (h *Histogram) Percentile(p float64) time.Duration {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.useHDR {
		return time.Duration(h.hdr.ValueAtPercentile(p)) * time.Microsecond
	}

	if len(h.values) == 0 {
		return 0
	}

	sorted := make([]time.Duration, len(h.values))
	copy(sorted, h.values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	idx := int(float64(len(sorted)-1) * p / 100)
	return sorted[idx]
}

func (h *Histogram) Mean() time.Duration {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.useHDR {
		return time.Duration(h.hdr.Mean()) * time.Microsecond
	}

	if len(h.values) == 0 {
		return 0
	}
	var sum time.Duration
	for _, v := range h.values {
		sum += v
	}
	return sum / time.Duration(len(h.values))
}

func (h *Histogram) StdDev() time.Duration {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.useHDR {
		return time.Duration(h.hdr.StdDev()) * time.Microsecond
	}

	if len(h.values) < 2 {
		return 0
	}
	mean := h.Mean()
	var sum float64
	for _, v := range h.values {
		diff := float64(v - mean)
		sum += diff * diff
	}
	return time.Duration(math.Sqrt(sum / float64(len(h.values))))
}

// ... rest of metrics.go stays the same

type LoadMetrics struct {
	Total       atomic.Uint64
	Success     atomic.Uint64
	Errors      atomic.Uint64
	Bytes       atomic.Uint64
	StartTime   time.Time
	EndTime     time.Time
	StatusCodes sync.Map // map[int]uint64
	Latencies   *Histogram
	ErrorTypes  sync.Map // map[string]uint64
	ActiveConns atomic.Int64
	mu          sync.RWMutex
	perSecond   []SecondMetrics
}

type SecondMetrics struct {
	Timestamp time.Time
	Requests  uint64
	Errors    uint64
	Bytes     uint64
}

func NewLoadMetrics() *LoadMetrics {
	return &LoadMetrics{
		StartTime: time.Now(),
		Latencies: NewHistogram(true),
	}
}

func (m *LoadMetrics) Record(success bool, latency time.Duration, bytes int64, statusCode int) {
	m.Total.Add(1)
	if success {
		m.Success.Add(1)
	} else {
		m.Errors.Add(1)
	}
	m.Bytes.Add(uint64(bytes))
	m.Latencies.Record(latency)

	if statusCode > 0 {
		key := statusCode
		if val, ok := m.StatusCodes.Load(key); ok {
			m.StatusCodes.Store(key, val.(uint64)+1)
		} else {
			m.StatusCodes.Store(key, uint64(1))
		}
	}
}

func (m *LoadMetrics) RecordError(errType string) {
	if val, ok := m.ErrorTypes.Load(errType); ok {
		m.ErrorTypes.Store(errType, val.(uint64)+1)
	} else {
		m.ErrorTypes.Store(errType, uint64(1))
	}
}

func (m *LoadMetrics) AddPerSecond() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.perSecond = append(m.perSecond, SecondMetrics{
		Timestamp: time.Now(),
		Requests:  m.Total.Load(),
		Errors:    m.Errors.Load(),
		Bytes:     m.Bytes.Load(),
	})
}

func (m *LoadMetrics) GetPerSecond() []SecondMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]SecondMetrics, len(m.perSecond))
	copy(result, m.perSecond)
	return result
}

func (m *LoadMetrics) Snapshot() map[string]interface{} {
	total := m.Total.Load()
	success := m.Success.Load()
	errors := m.Errors.Load()

	successRate := 0.0
	if total > 0 {
		successRate = float64(success) / float64(total) * 100
	}

	elapsed := time.Since(m.StartTime).Seconds()
	if !m.EndTime.IsZero() {
		elapsed = m.EndTime.Sub(m.StartTime).Seconds()
	}

	rps := 0.0
	if elapsed > 0 {
		rps = float64(total) / elapsed
	}

	// Collect status codes
	statusMap := make(map[string]uint64)
	m.StatusCodes.Range(func(key, value interface{}) bool {
		statusMap[fmt.Sprintf("%d", key)] = value.(uint64)
		return true
	})

	// Collect error types
	errorMap := make(map[string]uint64)
	m.ErrorTypes.Range(func(key, value interface{}) bool {
		errorMap[key.(string)] = value.(uint64)
		return true
	})

	return map[string]interface{}{
		"total":        total,
		"success":      success,
		"errors":       errors,
		"success_rate": successRate,
		"bytes":        m.Bytes.Load(),
		"bytes_human":  humanizeBytes(m.Bytes.Load()),
		"rps":          rps,
		"elapsed":      elapsed,
		"latency_avg":  m.Latencies.Mean().Milliseconds(),
		"latency_p50":  m.Latencies.Percentile(50).Milliseconds(),
		"latency_p95":  m.Latencies.Percentile(95).Milliseconds(),
		"latency_p99":  m.Latencies.Percentile(99).Milliseconds(),
		"latency_std":  m.Latencies.StdDev().Milliseconds(),
		"status_codes": statusMap,
		"error_types":  errorMap,
		"active_conns": m.ActiveConns.Load(),
	}
}

func humanizeBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
