package xhttp

// httpBackend wraps xhttp.Backend to implement lb.Backend interface
type httpBackend struct {
	*Backend
}

func (b httpBackend) Alive() bool     { return b.Backend.Alive.Load() }
func (b httpBackend) Weight() int     { return b.Backend.Weight }
func (b httpBackend) InFlight() int64 { return b.Backend.Activity.InFlight.Load() }

func (b httpBackend) ResponseTime() int64 {
	// Get average latency from metrics
	snap := b.Backend.Activity.Latency.Snapshot()
	if snap.Count == 0 {
		return 0
	}
	return snap.Avg
}
