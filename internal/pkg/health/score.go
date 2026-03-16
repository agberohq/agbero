package health

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const (
	scoreMax          = 100
	scoreMin          = 0
	scoreTrendUp      = 1
	scoreTrendDown    = -1
	scoreTrendFlat    = 0
	scoreSignificant  = 5
	latencyPerfect    = 100
	latencyBaseFactor = 30
	latencyMidFactor  = 70
	latencyExpBase    = 40
	latencyExpDiv     = 2000
)

type Record struct {
	ProbeLatency time.Duration
	ProbeSuccess bool
	StatusCode   int
	PassiveRate  float64
	ConnHealth   int32
}

type Weights struct {
	LatencyWeight float64
	SuccessWeight float64
	PassiveWeight float64
	ConnWeight    float64
}

type Latency struct {
	BaselineMs     int32
	DegradedFactor float64
	UnhealthyMs    int32
}

type Thresholds struct {
	HealthyMin   int32
	DegradedMax  int32
	UnhealthyMax int32
	DeadMax      int32

	DegradedExit  int32
	UnhealthyExit int32
	DeadExit      int32
}

type scoreSnapshot struct {
	value      int32
	state      State
	trend      int32
	lastUpdate time.Time
}

type Score struct {
	value            atomic.Int32
	state            atomic.Int32
	trend            atomic.Int32
	lastUpdate       atomic.Value
	lastPassiveReset atomic.Int64

	mu sync.RWMutex

	snapshot atomic.Value

	passiveErrors   atomic.Uint64
	passiveRequests atomic.Uint64
	connHealth      atomic.Int32

	consecFails atomic.Int64
	lastSuccess atomic.Int64
	lastFailure atomic.Int64

	thresholds        Thresholds
	scoringWeights    Weights
	latencyThresholds Latency

	onStateChange func(oldState, newState State, score int32)
}

// NewScore provisions a backend diagnostic tracker combining active and passive telemetry
// Automatically assigns perfect baseline ratings ensuring immediate availability
func NewScore(thresholds Thresholds, weights Weights, latThresholds Latency, onChange func(State, State, int32)) *Score {
	s := &Score{
		thresholds:        thresholds,
		scoringWeights:    weights,
		latencyThresholds: latThresholds,
		onStateChange:     onChange,
	}
	s.value.Store(scoreMax)
	s.state.Store(int32(StateUnknown))
	s.trend.Store(scoreTrendFlat)
	s.connHealth.Store(scoreMax)
	s.lastUpdate.Store(time.Now())
	s.lastPassiveReset.Store(time.Now().UnixNano())
	s.updateSnapshot()
	return s
}

// Value fetches the numeric index evaluating overall backend health
// Accessible instantaneously without mutex intervention
func (s *Score) Value() int32 {
	return s.value.Load()
}

// State returns the enumerated tier determining backend survivability
// Classifies numbers into easily readable systemic bands
func (s *Score) State() State {
	return State(s.state.Load())
}

// Status returns a human-readable string interpreting the current state
// Designed for operational dashboards and debugging outputs
func (s *Score) Status() Status {
	return State(s.state.Load()).Status()
}

// Trend assesses recent score movements indicating backend recovery or decay
// Retains positive, negative, or flat momentum indicators
func (s *Score) Trend() int32 {
	return s.trend.Load()
}

// LastUpdate records the chronologic moment when data was last synthesized
// Yields the most recent health check execution time safely
func (s *Score) LastUpdate() time.Time {
	if v := s.lastUpdate.Load(); v != nil {
		return v.(time.Time)
	}
	return time.Time{}
}

// ConsecutiveFailures tracks consecutive diagnostic interruptions sequentially
// Empowers early abort mechanisms recognizing repeated outages
func (s *Score) ConsecutiveFailures() int64 {
	return s.consecFails.Load()
}

// LastSuccess extracts the prior successful reachability timestamp
// Utilized calculating total accrued downtime sequences safely
func (s *Score) LastSuccess() time.Time {
	ts := s.lastSuccess.Load()
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(0, ts)
}

// LastFailure notes the most recent outage connection loss
// Defines periods of instability internally
func (s *Score) LastFailure() time.Time {
	ts := s.lastFailure.Load()
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(0, ts)
}

// Snapshot acquires a frozen state block combining all immediate metrics
// Eliminates race conditions parsing diverse atomic characteristics simultaneously
func (s *Score) Snapshot() scoreSnapshot {
	if v := s.snapshot.Load(); v != nil {
		return v.(scoreSnapshot)
	}
	return scoreSnapshot{}
}

// Update digests a new measurement modifying systemic trajectories appropriately
// Safely calculates combined scores adjusting thresholds seamlessly
func (s *Score) Update(r Record) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	if r.ProbeSuccess {
		s.lastSuccess.Store(now.UnixNano())
		s.consecFails.Store(0)
	} else {
		s.lastFailure.Store(now.UnixNano())
		s.consecFails.Add(1)
	}

	latencyScore := s.calculateLatencyScore(r.ProbeLatency)
	successScore := s.calculateSuccessScore(r.ProbeSuccess)

	if !r.ProbeSuccess {
		latencyScore = scoreMin
	}

	passiveScore := int32((1.0 - r.PassiveRate) * scoreMax)
	connScore := clamp(r.ConnHealth, scoreMin, scoreMax)

	newScore := int32(
		float64(latencyScore)*s.scoringWeights.LatencyWeight +
			float64(successScore)*s.scoringWeights.SuccessWeight +
			float64(passiveScore)*s.scoringWeights.PassiveWeight +
			float64(connScore)*s.scoringWeights.ConnWeight,
	)

	newScore = clamp(newScore, scoreMin, scoreMax)

	oldScore := s.value.Load()
	oldState := s.State()

	if newScore > oldScore+scoreSignificant {
		s.trend.Store(scoreTrendUp)
	} else if newScore < oldScore-scoreSignificant {
		s.trend.Store(scoreTrendDown)
	} else {
		s.trend.Store(scoreTrendFlat)
	}

	s.value.Store(newScore)
	s.lastUpdate.Store(now)

	newState := s.calculateState(oldState, newScore)
	if newState != oldState {
		s.state.Store(int32(newState))
		if s.onStateChange != nil {
			s.onStateChange(oldState, newState, newScore)
		}
	}

	s.passiveErrors.Swap(0)
	s.passiveRequests.Swap(0)
	s.updateSnapshot()
}

// updateSnapshot rewrites the structural grouping exposing safe telemetry values
// Guards memory against fragmented retrieval queries
func (s *Score) updateSnapshot() {
	s.snapshot.Store(scoreSnapshot{
		value:      s.value.Load(),
		state:      s.State(),
		trend:      s.trend.Load(),
		lastUpdate: s.LastUpdate(),
	})
}

// calculateState defines transition thresholds based on configured boundaries
// Stabilizes transitions avoiding flapping between degraded and healthy constantly
func (s *Score) calculateState(currentState State, score int32) State {
	t := s.thresholds

	switch currentState {
	case StateUnknown:
		if score >= t.DegradedExit {
			return StateHealthy
		}
		if score >= t.UnhealthyExit {
			return StateDegraded
		}
		if score > t.DeadMax {
			return StateUnhealthy
		}
		return StateDead

	case StateHealthy:
		if score <= t.DeadMax {
			return StateDead
		}
		if score <= t.UnhealthyMax {
			return StateUnhealthy
		}
		if score <= t.DegradedMax {
			return StateDegraded
		}
		return StateHealthy

	case StateDegraded:
		if score <= t.DeadMax {
			return StateDead
		}
		if score <= t.UnhealthyMax {
			return StateUnhealthy
		}
		if score >= t.DegradedExit {
			return StateHealthy
		}
		return StateDegraded

	case StateUnhealthy:
		if score <= t.DeadMax {
			return StateDead
		}
		if score >= t.UnhealthyExit {
			return StateDegraded
		}
		return StateUnhealthy

	case StateDead:
		if score >= t.DeadExit {
			return StateUnhealthy
		}
		return StateDead
	}

	return StateDead
}

// calculateLatencyScore creates performance bands matching request intervals
// Punishes high responses exponentially avoiding hardline cutoffs abruptly
func (s *Score) calculateLatencyScore(latency time.Duration) int32 {
	if latency <= 0 {
		return latencyPerfect
	}

	baseline := float64(s.latencyThresholds.BaselineMs)
	degraded := baseline * s.latencyThresholds.DegradedFactor
	unhealthy := float64(s.latencyThresholds.UnhealthyMs)
	ms := float64(latency.Milliseconds())

	switch {
	case ms <= baseline:
		return latencyPerfect
	case ms <= degraded:
		ratio := (ms - baseline) / (degraded - baseline)
		return int32(latencyPerfect - ratio*latencyBaseFactor)
	case ms <= unhealthy:
		ratio := (ms - degraded) / (unhealthy - degraded)
		return int32(latencyMidFactor - ratio*latencyBaseFactor)
	default:
		return int32(latencyExpBase * math.Exp(-(ms-unhealthy)/latencyExpDiv))
	}
}

// calculateSuccessScore provides baseline numbers for availability boolean states
// Translates simple pass or fail conditions into weighted metric allocations
func (s *Score) calculateSuccessScore(success bool) int32 {
	if success {
		return scoreMax
	}
	return scoreMin
}

// RecordPassiveRequest tracks internal data for responses between active polls
// Supplies accurate network viability independent of artificial diagnostics
func (s *Score) RecordPassiveRequest(success bool) {
	s.passiveRequests.Add(1)
	if !success {
		s.passiveErrors.Add(1)
	}
}

// PassiveErrorRate generates failure ratios tracking mid-interval instability
// Resets periodically mitigating long term metric staleness issues
func (s *Score) PassiveErrorRate() float64 {
	const passiveWindowNs = int64(60 * time.Second)

	now := time.Now().UnixNano()
	last := s.lastPassiveReset.Load()
	if now-last > passiveWindowNs {
		if s.lastPassiveReset.CompareAndSwap(last, now) {
			s.passiveErrors.Store(0)
			s.passiveRequests.Store(0)
			return 0
		}
	}

	reqs := s.passiveRequests.Load()
	if reqs == 0 {
		return 0
	}
	return float64(s.passiveErrors.Load()) / float64(reqs)
}

// SetConnHealth allows auxiliary systems to manipulate connection ratings directly
// Enforces bounds preserving functional thresholds implicitly
func (s *Score) SetConnHealth(health int32) {
	s.connHealth.Store(clamp(health, scoreMin, scoreMax))
}

// IsRapidDeterioration alerts subsystems regarding abrupt performance dropoffs
// Facilitates accelerated routing evacuations dodging cascading downtime
func (s *Score) IsRapidDeterioration() bool {
	lastUpdate := s.LastUpdate()
	if time.Since(lastUpdate) > 5*time.Second {
		return false
	}

	return s.trend.Load() == scoreTrendDown && s.value.Load() < 50
}

// ForceState overrides standard scoring bands forcing strict diagnostic evaluations
// Transmits notification callbacks informing external systems instantaneously
func (s *Score) ForceState(newState State) {
	oldState := State(s.state.Swap(int32(newState)))
	if oldState != newState && s.onStateChange != nil {
		s.onStateChange(oldState, newState, s.value.Load())
	}
	s.updateSnapshot()
}

// ForceHealthy dictates immediate system revival skipping graded ascensions
// Simplifies node restorations rapidly bridging artificial blockades
func (s *Score) ForceHealthy() {
	s.ForceState(StateHealthy)
}

// clamp restricts a value to be within the specified lower and upper bounds
// Prevents health scores from dropping below zero or exceeding one hundred
func clamp(v, lo, hi int32) int32 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
