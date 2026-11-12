package metrics

import (
	"sync/atomic"
)

const (
	maxCASRetries = 3
	ewmaWeight    = 9
	ewmaDivisor   = 10
	incrementUnit = 1
	emptyValue    = 0
)

type Activity struct {
	InFlight   atomic.Int64
	Requests   atomic.Uint64
	Failures   atomic.Uint64
	BytesIn    atomic.Uint64
	BytesOut   atomic.Uint64
	Datagrams  atomic.Uint64
	WebSockets atomic.Int64
	Latency    *Latency
	ewmaUs     atomic.Int64
}

// NewActivity instantiates operational tracking telemetry
// Manages concurrency inflight counters and throughput latency
func NewActivity() *Activity {
	return &Activity{
		Latency: NewLatency(),
	}
}

// StartRequest increases the active connection count
// Operates automatically and block-free for inbound traffic tracking
func (at *Activity) StartRequest() {
	at.InFlight.Add(incrementUnit)
}

// EndRequest decreases active counts and archives the outcome performance
// Decrements immediately while asynchronously evaluating moving averages
func (at *Activity) EndRequest(duration int64, isFailure bool) {
	at.Requests.Add(incrementUnit)
	if isFailure {
		at.Failures.Add(incrementUnit)
	}
	at.Latency.Record(duration)
	at.InFlight.Add(-incrementUnit)

	at.updateEWMA(duration)
}

// updateEWMA recalculates the exponential weighted moving average of response times
// Uses a bounded compare-and-swap loop to heavily reduce silent drops under load
func (at *Activity) updateEWMA(duration int64) {
	for i := 0; i < maxCASRetries; i++ {
		old := at.ewmaUs.Load()
		var next int64
		if old == emptyValue {
			next = duration
		} else {
			next = (duration + ewmaWeight*old) / ewmaDivisor
		}
		if at.ewmaUs.CompareAndSwap(old, next) {
			break
		}
	}
}

// Snapshot freezes ongoing values into a secure map extraction
// Yields current telemetry structures for reporting components
func (at *Activity) Snapshot() map[string]any {
	lat := at.Latency.Snapshot()
	return map[string]any{
		"in_flight":  at.InFlight.Load(),
		"requests":   at.Requests.Load(),
		"failures":   at.Failures.Load(),
		"bytes_in":   at.BytesIn.Load(),
		"bytes_out":  at.BytesOut.Load(),
		"datagrams":  at.Datagrams.Load(),
		"websockets": at.WebSockets.Load(),
		"latency":    lat,
		"ewma_us":    at.ewmaUs.Load(),
	}
}

// AddBytes records tunnel/application bytes by direction.
func (at *Activity) AddBytes(in, out uint64) {
	if in > 0 {
		at.BytesIn.Add(in)
	}
	if out > 0 {
		at.BytesOut.Add(out)
	}
}

// AddDatagram records one forwarded datagram.
func (at *Activity) AddDatagram() { at.Datagrams.Add(1) }

// AddWebSocket tracks currently open WebSocket tunnels.
func (at *Activity) AddWebSocket(delta int64) { at.WebSockets.Add(delta) }

// EWMA delivers the latest known exponential weight average output
// Provides lock-free access to traffic speed approximations
func (at *Activity) EWMA() int64 {
	return at.ewmaUs.Load()
}

// Close shuts down the latency tracker
func (at *Activity) Close() {
	if at.Latency != nil {
		at.Latency.Close()
	}
}
