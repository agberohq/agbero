package upstream

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/agberohq/agbero/internal/pkg/metrics"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/jack"
)

const DefaultHalfOpenCooldown = int64(5 * time.Second)

type Config struct {
	Address        string
	Weight         int
	MaxConnections int64
	CBThreshold    int64
	HasProber      bool
	StatsKey       alaye.BackendKey
	Resource       *resource.Resource
}

func (c Config) Validate() error {
	if c.Address == "" {
		return errors.New("address is required")
	}
	if c.Resource == nil {
		return errors.New("resource manager is required")
	}
	if c.Resource.Metrics == nil || c.Resource.Health == nil {
		return errors.New("resource manager is missing required components")
	}
	return nil
}

type Base struct {
	Address     string
	WeightVal   int
	MaxConns    int64
	CBThreshold int64
	HasProber   bool
	StatsKey    alaye.BackendKey

	Activity    *metrics.Activity
	HealthScore *health.Score
	Weights     health.Multiplier

	StartTime time.Time
	LastRecov atomic.Int64

	resource  *resource.Resource
	PatientID string
}

func NewBase(c Config) (Base, error) {
	if err := c.Validate(); err != nil {
		return Base{}, err
	}

	weight := c.Weight
	if weight <= 0 {
		weight = 1
	}

	stats := c.Resource.Metrics.GetOrRegister(c.StatsKey)
	hScore := c.Resource.Health.GetOrSet(c.StatsKey, health.NewScore(health.DefaultThresholds(), health.DefaultScoringWeights(), health.DefaultLatencyThresholds(), nil))

	now := time.Now()
	b := Base{
		Address:     c.Address,
		WeightVal:   weight,
		MaxConns:    c.MaxConnections,
		CBThreshold: c.CBThreshold,
		HasProber:   c.HasProber,
		StatsKey:    c.StatsKey,
		Activity:    stats.Activity,
		HealthScore: hScore,
		Weights:     health.DefaultRoutingMultiplier(),
		StartTime:   now,
		resource:    c.Resource,
	}
	b.LastRecov.Store(now.UnixNano())
	return b, nil
}

func (b *Base) Status(v bool) {
	if !v {
		b.HealthScore.Update(health.Record{
			ProbeSuccess: false,
			ConnHealth:   30,
			PassiveRate:  0.6,
		})
		if b.CBThreshold > 0 {
			b.Activity.Failures.Store(uint64(b.CBThreshold + 1))
		}
	} else {
		b.HealthScore.Update(health.Record{
			ProbeLatency: 10 * time.Millisecond,
			ProbeSuccess: true,
			ConnHealth:   100,
			PassiveRate:  0,
		})
		b.HealthScore.ForceHealthy()
		b.Activity.Failures.Store(0)
	}
}

func (b *Base) Alive() bool {
	if b.CBThreshold > 0 {
		if b.Activity.Failures.Load() >= uint64(b.CBThreshold) {
			lastRecov := b.LastRecov.Load()
			now := time.Now().UnixNano()
			if now-lastRecov > DefaultHalfOpenCooldown {
				return true
			}
			return false
		}
	}
	if b.HealthScore != nil {
		state := b.HealthScore.State()
		if state == health.StateDead || state == health.StateUnhealthy {
			return false
		}
	}
	return true
}

func (b *Base) AcquireCircuit() bool {
	if b.CBThreshold <= 0 {
		return true
	}
	if b.Activity.Failures.Load() < uint64(b.CBThreshold) {
		return true
	}

	lastRecov := b.LastRecov.Load()
	now := time.Now().UnixNano()
	if now-lastRecov > DefaultHalfOpenCooldown {
		if b.LastRecov.CompareAndSwap(lastRecov, now) {
			return true
		}
	}
	return false
}

func (b *Base) RecordResult(success bool) bool {
	if success {
		b.Activity.Failures.Store(0)
		return false
	}

	failures := b.Activity.Failures.Load()

	// Only stamp LastRecov when the circuit first trips.
	// Do NOT update it on subsequent failures — that is the stun-lock bug.
	if b.CBThreshold > 0 && failures == uint64(b.CBThreshold) {
		b.LastRecov.Store(time.Now().UnixNano())
	}

	return b.CBThreshold > 0 && failures >= uint64(b.CBThreshold)
}

func (b *Base) IsUsable() bool {
	if !b.Alive() {
		return false
	}
	if b.MaxConns > 0 && b.Activity.InFlight.Load() >= b.MaxConns {
		return false
	}
	return true
}

func (b *Base) Weight() int {
	if b.HealthScore == nil {
		return b.WeightVal
	}
	return b.Weights.EffectiveWeight(b.WeightVal, b.HealthScore)
}

func (b *Base) InFlight() int64 {
	return b.Activity.InFlight.Load()
}

func (b *Base) ResponseTime() int64 {
	v := b.Activity.EWMA()
	if v == 0 {
		return 0
	}
	return v
}

func (b *Base) OnDialFailure(err error) {
	b.Activity.Failures.Add(1)
	b.RecordResult(false)
	if b.HealthScore != nil {
		b.HealthScore.RecordPassiveRequest(false)
	}
}

func (b *Base) Uptime() time.Duration {
	return time.Since(b.StartTime)
}

func (b *Base) LastRecovery() time.Time {
	return time.Unix(0, b.LastRecov.Load())
}

func (b *Base) RegisterHealth(probeCfg health.ProbeConfig, checkFn func(ctx context.Context) error, onRemove func()) error {
	if !b.HasProber {
		return nil
	}
	if b.resource.Doctor == nil {
		return errors.New("doctor is nil")
	}

	b.PatientID = b.StatsKey.ID(b.resource.NextID())
	patient := jack.NewPatient(jack.PatientConfig{
		ID:       b.PatientID,
		Interval: probeCfg.StandardInterval,
		Timeout:  probeCfg.Timeout,
		Check:    checkFn,
		OnRemove: onRemove,
	})

	return b.resource.Doctor.Add(patient)
}

func (b *Base) Doctor() any {
	if b.resource == nil {
		return nil
	}
	return b.resource.Doctor
}
