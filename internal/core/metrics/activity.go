package metrics

import (
	"sync/atomic"
)

type Activity struct {
	InFlight atomic.Int64
	Requests atomic.Uint64
	Failures atomic.Uint64
	Latency  *Latency
}

func NewActivityTracker() *Activity {
	return &Activity{
		Latency: NewLatency(),
	}
}

func (at *Activity) StartRequest() {
	at.InFlight.Add(1)
}

func (at *Activity) EndRequest(duration int64, failed bool) {
	at.InFlight.Add(-1)
	at.Requests.Add(1)
	if failed {
		at.Failures.Add(1)
	}
	at.Latency.Record(duration)
}

func (at *Activity) Snapshot() map[string]interface{} {
	lat := at.Latency.Snapshot()
	return map[string]interface{}{
		"in_flight": at.InFlight.Load(),
		"requests":  at.Requests.Load(),
		"failures":  at.Failures.Load(),
		"latency":   lat,
	}
}
