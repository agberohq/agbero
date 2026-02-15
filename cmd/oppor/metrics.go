package main

import (
	"sync/atomic"
	"time"
)

type Metrics struct {
	TotalRequests     atomic.Uint64
	SuccessCount      atomic.Uint64
	ErrorCount        atomic.Uint64
	TotalLatency      atomic.Uint64 // microseconds
	MinLatency        atomic.Uint64
	MaxLatency        atomic.Uint64
	TotalBytes        atomic.Uint64
	RequestsPerSec    atomic.Uint64
	ActiveConnections atomic.Int32

	// Enabled code distribution
	StatusCode2xx atomic.Uint64
	StatusCode3xx atomic.Uint64
	StatusCode4xx atomic.Uint64
	StatusCode5xx atomic.Uint64

	// Latency histogram
	LatencyBuckets [10]atomic.Uint64 // 0-10ms, 10-50ms, 50-100ms, 100-250ms, 250-500ms, 500-1000ms, 1-2s, 2-5s, 5-10s, 10s+
}

func (m *Metrics) Record(latency time.Duration, status int, bytes int64, err error) {
	m.TotalRequests.Add(1)
	m.TotalBytes.Add(uint64(bytes))

	latencyUs := uint64(latency.Microseconds())
	m.TotalLatency.Add(latencyUs)

	// Update min/max
	for {
		currentMin := m.MinLatency.Load()
		if currentMin != 0 && latencyUs >= currentMin {
			break
		}
		if m.MinLatency.CompareAndSwap(currentMin, latencyUs) {
			break
		}
	}
	for {
		currentMax := m.MaxLatency.Load()
		if currentMax != 0 && latencyUs <= currentMax {
			break
		}
		if m.MaxLatency.CompareAndSwap(currentMax, latencyUs) {
			break
		}
	}

	// Update status codes
	if err != nil {
		m.ErrorCount.Add(1)
	} else {
		m.SuccessCount.Add(1)
		switch {
		case status >= 200 && status < 300:
			m.StatusCode2xx.Add(1)
		case status >= 300 && status < 400:
			m.StatusCode3xx.Add(1)
		case status >= 400 && status < 500:
			m.StatusCode4xx.Add(1)
		case status >= 500:
			m.StatusCode5xx.Add(1)
		}
	}

	// Update latency bucket
	latencyMs := latency.Milliseconds()
	switch {
	case latencyMs < 10:
		m.LatencyBuckets[0].Add(1)
	case latencyMs < 50:
		m.LatencyBuckets[1].Add(1)
	case latencyMs < 100:
		m.LatencyBuckets[2].Add(1)
	case latencyMs < 250:
		m.LatencyBuckets[3].Add(1)
	case latencyMs < 500:
		m.LatencyBuckets[4].Add(1)
	case latencyMs < 1000:
		m.LatencyBuckets[5].Add(1)
	case latencyMs < 2000:
		m.LatencyBuckets[6].Add(1)
	case latencyMs < 5000:
		m.LatencyBuckets[7].Add(1)
	case latencyMs < 10000:
		m.LatencyBuckets[8].Add(1)
	default:
		m.LatencyBuckets[9].Add(1)
	}
}

func (m *Metrics) Snapshot() MetricsSnapshot {
	total := m.TotalRequests.Load()
	success := m.SuccessCount.Load()
	errors := m.ErrorCount.Load()

	var avgLatency float64
	if success > 0 {
		avgLatency = float64(m.TotalLatency.Load()) / float64(success) / 1000.0 // in ms
	}

	successRate := 0.0
	if total > 0 {
		successRate = float64(success) / float64(total) * 100
	}

	return MetricsSnapshot{
		TotalRequests:     total,
		SuccessCount:      success,
		ErrorCount:        errors,
		SuccessRate:       successRate,
		AvgLatencyMs:      avgLatency,
		MinLatencyMs:      float64(m.MinLatency.Load()) / 1000.0,
		MaxLatencyMs:      float64(m.MaxLatency.Load()) / 1000.0,
		RequestsPerSec:    m.RequestsPerSec.Load(),
		ThroughputMBps:    float64(m.TotalBytes.Load()) / (1024 * 1024),
		ActiveConnections: m.ActiveConnections.Load(),
		StatusCode2xx:     m.StatusCode2xx.Load(),
		StatusCode3xx:     m.StatusCode3xx.Load(),
		StatusCode4xx:     m.StatusCode4xx.Load(),
		StatusCode5xx:     m.StatusCode5xx.Load(),
		TotalBytes:        m.TotalBytes.Load(),
	}
}

type MetricsSnapshot struct {
	TotalRequests     uint64  `json:"total_requests"`
	SuccessCount      uint64  `json:"success_count"`
	ErrorCount        uint64  `json:"error_count"`
	SuccessRate       float64 `json:"success_rate"`
	AvgLatencyMs      float64 `json:"avg_latency_ms"`
	MinLatencyMs      float64 `json:"min_latency_ms"`
	MaxLatencyMs      float64 `json:"max_latency_ms"`
	RequestsPerSec    uint64  `json:"requests_per_sec"`
	ThroughputMBps    float64 `json:"throughput_mbps"`
	ActiveConnections int32   `json:"active_connections"`
	StatusCode2xx     uint64  `json:"status_2xx"`
	StatusCode3xx     uint64  `json:"status_3xx"`
	StatusCode4xx     uint64  `json:"status_4xx"`
	StatusCode5xx     uint64  `json:"status_5xx"`
	TotalBytes        uint64  `json:"total_bytes"`
}
