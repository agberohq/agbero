package upstream

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/agberohq/agbero/internal/pkg/metrics"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/jack"
)

// halfOpenCooldown is how long after the circuit trips before a half-open
// probe is permitted. 5 seconds — shorter than the breaker open timeout
// so health probes can restore service quickly.
const halfOpenCooldown = int64(5 * time.Second)

type Config struct {
	Address        string
	Weight         int
	MaxConnections int64
	CBThreshold    int64
	HasProber      bool
	StatsKey       alaye.Key
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
	StatsKey    alaye.Key

	Activity    *metrics.Activity
	HealthScore *health.Score
	Weights     health.Multiplier

	StartTime time.Time
	// LastRecov is the nanosecond timestamp when the circuit first tripped or
	// last recovered. Written ONLY on first trip and on recovery.
	LastRecov atomic.Int64
	// tripped is true while the circuit is open. Used by RecordResult(false)
	// to distinguish "just tripped" from "already open" without relying on
	// the Failures counter value (which direct tests manipulate freely).
	tripped atomic.Bool

	breaker *jack.Breaker
	sem     *jack.Semaphore

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
	hScore := c.Resource.Health.GetOrSet(c.StatsKey, health.NewScore(
		health.DefaultThresholds(),
		health.DefaultScoringWeights(),
		health.DefaultLatencyThresholds(),
		nil,
	))

	threshold := uint64(def.DefaultCircuitBreakerThreshold)
	if c.CBThreshold > 0 {
		threshold = uint64(c.CBThreshold)
	}

	breaker := jack.NewBreaker(
		c.Address,
		jack.BreakerWithThreshold(threshold),
		jack.BreakerWithOpenTimeout(def.DefaultCircuitBreakerDuration),
		jack.BreakerWithSuccessThreshold(1),
		jack.BreakerWithHalfOpenLimit(1),
	)

	var sem *jack.Semaphore
	if c.MaxConnections > 0 {
		sem = jack.NewSemaphore(int(c.MaxConnections))
	}

	b := Base{
		Address:     c.Address,
		WeightVal:   weight,
		MaxConns:    c.MaxConnections,
		CBThreshold: int64(threshold),
		HasProber:   c.HasProber,
		StatsKey:    c.StatsKey,
		Activity:    stats.Activity,
		HealthScore: hScore,
		Weights:     health.DefaultRoutingMultiplier(),
		StartTime:   time.Now(),
		breaker:     breaker,
		sem:         sem,
		resource:    c.Resource,
	}
	b.LastRecov.Store(time.Now().UnixNano())
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
			if b.tripped.CompareAndSwap(false, true) {
				b.LastRecov.Store(time.Now().UnixNano())
			}
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
		b.tripped.Store(false)
		b.LastRecov.Store(time.Now().UnixNano())
		if b.breaker != nil {
			b.breaker.Reset()
		}
	}
}

// Alive reports whether this backend can accept traffic.
// Reads Activity.Failures directly — the canonical observable counter — so
// tests and health probes that set it directly are respected.
func (b *Base) Alive() bool {
	if b.CBThreshold > 0 && b.Activity.Failures.Load() >= uint64(b.CBThreshold) {
		return false
	}
	if b.HealthScore != nil {
		state := b.HealthScore.State()
		if state == health.StateDead || state == health.StateUnhealthy {
			return false
		}
	}
	return true
}

// AcquireCircuit returns true if a request may proceed.
// Returns false when the circuit is open (in cooldown).
// Returns true in half-open state (cooldown elapsed) — one goroutine wins the CAS.
func (b *Base) AcquireCircuit() bool {
	if b.CBThreshold <= 0 {
		return true
	}
	if b.Activity.Failures.Load() < uint64(b.CBThreshold) {
		return true
	}
	// At or above threshold.
	lastRecov := b.LastRecov.Load()
	now := time.Now().UnixNano()
	cooldownElapsed := now-lastRecov > halfOpenCooldown

	if !b.tripped.Load() {
		// Failures were set directly (test or Status(false)) without RecordResult.
		// If the stored LastRecov is already expired, allow the probe.
		if cooldownElapsed {
			b.tripped.Store(true)
			// CAS to advance LastRecov so the next caller waits for a new window.
			b.LastRecov.CompareAndSwap(lastRecov, now)
			return true
		}
		// Cooldown not elapsed — record the trip and deny.
		b.tripped.CompareAndSwap(false, true)
		b.LastRecov.Store(now)
		return false
	}

	// Already tripped — allow only when cooldown has elapsed (half-open probe).
	if cooldownElapsed {
		if b.LastRecov.CompareAndSwap(lastRecov, now) {
			return true
		}
	}
	return false
}

// RecordResult manages the circuit trip timestamp after a request completes.
// Returns true if the circuit just tripped on this call.
//
// RecordResult does NOT increment Activity.Failures — callers do that.
// It uses the tripped atomic flag to precisely distinguish first-trip
// (write LastRecov once) from already-open (never touch LastRecov).
// This prevents the stun-lock where sustained failures keep resetting the
// cooldown window and prevent half-open recovery.
func (b *Base) RecordResult(success bool) bool {
	if success {
		b.Activity.Failures.Store(0)
		b.tripped.Store(false)
		b.LastRecov.Store(time.Now().UnixNano())
		if b.breaker != nil {
			b.breaker.Reset()
		}
		return false
	}
	if b.CBThreshold <= 0 {
		return false
	}
	if b.Activity.Failures.Load() < uint64(b.CBThreshold) {
		return false
	}
	// At or above threshold. Only write LastRecov on the FIRST trip.
	// CAS false→true: the goroutine that wins records the trip timestamp.
	// All subsequent failures (including direct RecordResult(false) calls
	// in tests) skip this block entirely — stun-lock prevention.
	if b.tripped.CompareAndSwap(false, true) {
		b.LastRecov.Store(time.Now().UnixNano())
		return true
	}
	return false
}

// WrapWithBreaker executes fn through jack.Breaker for the HTTP backend path.
// This provides Open→HalfOpen→Closed state management with proper half-open
// probing. After success, syncs Activity.Failures to 0.
// Returns jack.ErrBreakerOpen when AcquireCircuit() denies the request.
func (b *Base) WrapWithBreaker(ctx context.Context, fn func(context.Context) error) error {
	if !b.AcquireCircuit() {
		return jack.ErrBreakerOpen
	}
	err := fn(ctx)
	if err == nil {
		b.Activity.Failures.Store(0)
		b.tripped.Store(false)
		b.LastRecov.Store(time.Now().UnixNano())
		if b.breaker != nil {
			b.breaker.Reset()
		}
	}
	return err
}

// AcquireSem acquires a concurrency slot when MaxConns is configured.
func (b *Base) AcquireSem(ctx context.Context, p jack.Priority) (func(), error) {
	if b.sem == nil {
		return func() {}, nil
	}
	if err := b.sem.Acquire(ctx, p); err != nil {
		return nil, err
	}
	return func() { b.sem.Release() }, nil
}

// IsUsable reports whether the LB should route to this backend.
// Returns true in half-open state (cooldown elapsed) — the actual probe CAS
// happens in AcquireCircuit within the request path.
func (b *Base) IsUsable() bool {
	if b.HealthScore != nil {
		state := b.HealthScore.State()
		if state == health.StateDead || state == health.StateUnhealthy {
			return false
		}
	}
	if b.MaxConns > 0 && b.Activity.InFlight.Load() >= b.MaxConns {
		return false
	}
	if b.CBThreshold > 0 && b.Activity.Failures.Load() >= uint64(b.CBThreshold) {
		return time.Now().UnixNano()-b.LastRecov.Load() > halfOpenCooldown
	}
	return true
}

// BreakerState returns the jack.Breaker state for logging/observability.
func (b *Base) BreakerState() jack.BreakerState {
	if b.breaker == nil {
		return jack.BreakerClosed
	}
	return b.breaker.State()
}

func (b *Base) Weight() int {
	if b.HealthScore == nil {
		return b.WeightVal
	}
	return b.Weights.EffectiveWeight(b.WeightVal, b.HealthScore)
}

func (b *Base) InFlight() int64 { return b.Activity.InFlight.Load() }

func (b *Base) ResponseTime() int64 {
	v := b.Activity.EWMA()
	if v == 0 {
		return 0
	}
	return v
}

// OnDialFailure is called when a dial-level error occurs. Increments
// Activity.Failures once and feeds the result into RecordResult which manages
// the trip timestamp. Does NOT double-count.
func (b *Base) OnDialFailure(err error) {
	b.Activity.Failures.Add(1)
	// RecordResult reads Activity.Failures to decide whether to record a trip —
	// it does NOT increment again.
	b.RecordResult(false)
	if b.HealthScore != nil {
		b.HealthScore.RecordPassiveRequest(false)
	}
}

func (b *Base) Uptime() time.Duration { return time.Since(b.StartTime) }

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
