package metrics

import (
	"sync/atomic"
)

type Activity struct {
	InFlight atomic.Int64
	Requests atomic.Uint64
	Failures atomic.Uint64
	Latency  *Latency
	ewmaUs   atomic.Int64
}

func NewActivity() *Activity {
	return &Activity{
		Latency: NewLatency(),
	}
}

func (at *Activity) StartRequest() {
	at.InFlight.Add(1)
}

func (at *Activity) EndRequest(duration int64, isFailure bool) {
	at.Requests.Add(1)
	if isFailure {
		at.Failures.Add(1)
	}
	at.Latency.Record(duration)
	at.InFlight.Add(-1)

	// Simplified EWMA - atomic store instead of CAS loop
	// EWMA is approximate anyway, strict CAS not worth the contention cost
	old := at.ewmaUs.Load()
	if old == 0 {
		at.ewmaUs.Store(duration)
	} else {
		at.ewmaUs.Store((duration + 9*old) / 10)
	}
}

func (at *Activity) Snapshot() map[string]any {
	lat := at.Latency.Snapshot()
	return map[string]any{
		"in_flight": at.InFlight.Load(),
		"requests":  at.Requests.Load(),
		"failures":  at.Failures.Load(),
		"latency":   lat,
		"ewma_us":   at.ewmaUs.Load(),
	}
}

func (at *Activity) EWMA() int64 {
	return at.ewmaUs.Load()
}
