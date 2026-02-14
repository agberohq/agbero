package xtcp

// tcpBackend wraps xtcp.Backend to implement lb.Backend interface
type tcpBackend struct {
	*Backend
}

func (b tcpBackend) Alive() bool     { return b.Backend.Alive.Load() }
func (b tcpBackend) Weight() int     { return b.Backend.Weight }
func (b tcpBackend) InFlight() int64 { return b.Backend.Activity.InFlight.Load() }
func (b tcpBackend) ResponseTime() int64 {
	snap := b.Backend.Activity.Latency.Snapshot()
	if snap.Count == 0 {
		return 0
	}
	return snap.Avg
}
