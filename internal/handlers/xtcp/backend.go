package xtcp

import (
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/agberohq/agbero/internal/pkg/lb"
	"github.com/agberohq/agbero/internal/pkg/metrics"
)

type Backend struct {
	Address  string
	Activity *metrics.Activity

	MaxConns int64

	HealthScore *health.Score
	Weights     health.Multiplier

	hasProber  bool
	weight     int
	failThresh int64

	stop     chan struct{}
	stopOnce sync.Once
}

func (b *Backend) HasProber() bool {
	return b.hasProber
}

func (b *Backend) Stop() {
	b.stopOnce.Do(func() {
		close(b.stop)
	})
}

func (b *Backend) OnDialFailure(_ error) {
	b.Activity.Failures.Add(1)
	if b.HealthScore != nil {
		b.HealthScore.RecordPassiveRequest(false)
		b.HealthScore.Update(health.Record{
			ProbeSuccess: false,
			ConnHealth:   0,
			PassiveRate:  b.HealthScore.PassiveErrorRate(),
		})
	}
}

func (b *Backend) Snapshot() *Snapshot {
	return &Snapshot{
		Address:     b.Address,
		Alive:       b.Alive(),
		ActiveConns: b.Activity.InFlight.Load(),
		Failures:    int64(b.Activity.Failures.Load()),
		MaxConns:    b.MaxConns,
		TotalReqs:   b.Activity.Requests.Load(),
		Latency:     b.Activity.Latency.Snapshot(),
	}
}

func (b *Backend) Status(v bool) {
	if !v {
		b.HealthScore.Update(health.Record{
			ProbeSuccess: false,
			ConnHealth:   0,
			PassiveRate:  1.0,
		})
		b.Activity.Failures.Store(uint64(b.failThresh + 1))
	} else {
		b.HealthScore.Update(health.Record{
			ProbeLatency: 10 * time.Millisecond,
			ProbeSuccess: true,
			ConnHealth:   100,
			PassiveRate:  0,
		})
		b.Activity.Failures.Store(0)
	}
}

func (b *Backend) Alive() bool {
	if b.failThresh > 0 && b.Activity.Failures.Load() >= uint64(b.failThresh) {
		return false
	}
	if !b.hasProber || b.HealthScore == nil {
		return true
	}
	state := b.HealthScore.State()
	return state != health.StateDead && state != health.StateUnhealthy
}

func (b *Backend) Weight() int {
	if b.HealthScore == nil {
		return b.weight
	}
	return b.Weights.EffectiveWeight(b.weight, b.HealthScore)
}

func (b *Backend) InFlight() int64 { return b.Activity.InFlight.Load() }

func (b *Backend) ResponseTime() int64 {
	snap := b.Activity.Latency.Snapshot()
	if snap.Count == 0 {
		return 0
	}
	return snap.Avg
}

var _ lb.Backend = (*Backend)(nil)
