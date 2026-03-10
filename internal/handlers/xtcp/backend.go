package xtcp

import (
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/pkg/health"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/lb"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/metrics"
)

type Backend struct {
	Address  string
	Activity *metrics.Activity
	Health   *metrics.Health // Legacy

	MaxConns int64

	// New Health Components
	HealthScore *health.Score
	Prober      *health.Prober
	Weights     health.RoutingWeights

	hcInterval time.Duration
	hcTimeout  time.Duration
	hcSend     []byte
	hcExpect   []byte
	weight     int
	failThresh int64

	stop     chan struct{}
	stopOnce sync.Once
	pool     *connPool
	poolOnce sync.Once
}

func (b *Backend) Stop() {
	b.stopOnce.Do(func() {
		close(b.stop)
		if b.Prober != nil {
			b.Prober.Stop()
		}
		b.poolOnce.Do(func() {
			if b.pool != nil {
				b.pool.close()
			}
		})
	})
}

func (b *Backend) OnDialFailure(_ error) {
	b.Activity.Failures.Add(1)
	b.HealthScore.RecordPassiveRequest(false)
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

func (b *Backend) StartHealthCheck() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[CRITICAL] TCP health check panic for %s: %v\nStack: %s\n", b.Address, r, debug.Stack())
		}
	}()

	b.poolOnce.Do(func() {
		b.pool = newConnPool(b.Address, 3, b.hcTimeout)
	})

	probeCfg := health.DefaultProbeConfig()
	if b.hcInterval > 0 {
		probeCfg.StandardInterval = b.hcInterval
		// Ensure acceleration doesn't accidentally slow down fast checks
		if probeCfg.AcceleratedInterval > probeCfg.StandardInterval {
			probeCfg.AcceleratedInterval = probeCfg.StandardInterval
		}
	}
	if b.hcTimeout > 0 {
		probeCfg.Timeout = b.hcTimeout
	}

	executor := &TCPExecutor{
		Pool:   b.pool,
		Send:   b.hcSend,
		Expect: b.hcExpect,
	}

	b.HealthScore = health.NewScore(
		health.DefaultThresholds(),
		health.DefaultScoringWeights(),
		health.DefaultLatencyThresholds(),
		nil,
	)
	b.Weights = health.DefaultRoutingWeights()

	b.Prober = health.NewProber(probeCfg, executor, b.HealthScore, func(r health.ProbeResult) {
		if r.Success {
			b.Health.RecordSuccess()
			b.Activity.Failures.Store(0)
		} else {
			b.Health.RecordFailure()
		}
	})

	b.Prober.Start()
}

func (b *Backend) Status(v bool) {
	// No-op
}

func (b *Backend) Alive() bool {
	if b.failThresh > 0 && b.Activity.Failures.Load() >= uint64(b.failThresh) {
		return false
	}
	return b.HealthScore.State() != health.StateDead
}

func (b *Backend) Weight() int {
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
