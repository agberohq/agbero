package health

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
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
	value      atomic.Int32
	state      atomic.Int32
	trend      atomic.Int32
	lastUpdate atomic.Value

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

func NewScore(thresholds Thresholds, weights Weights, latThresholds Latency, onChange func(State, State, int32)) *Score {
	s := &Score{
		thresholds:        thresholds,
		scoringWeights:    weights,
		latencyThresholds: latThresholds,
		onStateChange:     onChange,
	}
	s.value.Store(100)
	s.state.Store(int32(StateUnknown))
	s.trend.Store(0)
	s.connHealth.Store(100)
	s.lastUpdate.Store(time.Now())
	s.updateSnapshot()
	return s
}

func (s *Score) Value() int32 {
	return s.value.Load()
}

func (s *Score) State() State {
	return State(s.state.Load())
}

func (s *Score) Status() Status {
	return State(s.state.Load()).Status()
}

func (s *Score) Trend() int32 {
	return s.trend.Load()
}

func (s *Score) LastUpdate() time.Time {
	if v := s.lastUpdate.Load(); v != nil {
		return v.(time.Time)
	}
	return time.Time{}
}

func (s *Score) ConsecutiveFailures() int64 {
	return s.consecFails.Load()
}

func (s *Score) LastSuccess() time.Time {
	ts := s.lastSuccess.Load()
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(0, ts)
}

func (s *Score) LastFailure() time.Time {
	ts := s.lastFailure.Load()
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(0, ts)
}

func (s *Score) Snapshot() scoreSnapshot {
	if v := s.snapshot.Load(); v != nil {
		return v.(scoreSnapshot)
	}
	return scoreSnapshot{}
}

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
		latencyScore = 0
	}

	passiveScore := int32((1.0 - r.PassiveRate) * 100)
	connScore := clamp(r.ConnHealth, 0, 100)

	newScore := int32(
		float64(latencyScore)*s.scoringWeights.LatencyWeight +
			float64(successScore)*s.scoringWeights.SuccessWeight +
			float64(passiveScore)*s.scoringWeights.PassiveWeight +
			float64(connScore)*s.scoringWeights.ConnWeight,
	)

	newScore = clamp(newScore, 0, 100)

	oldScore := s.value.Load()
	oldState := s.State()

	if newScore > oldScore+5 {
		s.trend.Store(1)
	} else if newScore < oldScore-5 {
		s.trend.Store(-1)
	} else {
		s.trend.Store(0)
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

	s.updateSnapshot()
}

func (s *Score) updateSnapshot() {
	s.snapshot.Store(scoreSnapshot{
		value:      s.value.Load(),
		state:      s.State(),
		trend:      s.trend.Load(),
		lastUpdate: s.LastUpdate(),
	})
}

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

func (s *Score) calculateLatencyScore(latency time.Duration) int32 {
	if latency <= 0 {
		return 100
	}

	baseline := float64(s.latencyThresholds.BaselineMs)
	degraded := baseline * s.latencyThresholds.DegradedFactor
	unhealthy := float64(s.latencyThresholds.UnhealthyMs)
	ms := float64(latency.Milliseconds())

	switch {
	case ms <= baseline:
		return 100
	case ms <= degraded:
		ratio := (ms - baseline) / (degraded - baseline)
		return int32(100 - ratio*30)
	case ms <= unhealthy:
		ratio := (ms - degraded) / (unhealthy - degraded)
		return int32(70 - ratio*30)
	default:
		return int32(40 * math.Exp(-(ms-unhealthy)/2000))
	}
}

func (s *Score) calculateSuccessScore(success bool) int32 {
	if success {
		return 100
	}
	return 0
}

func (s *Score) RecordPassiveRequest(success bool) {
	s.passiveRequests.Add(1)
	if !success {
		s.passiveErrors.Add(1)
	}
}

func (s *Score) PassiveErrorRate() float64 {
	reqs := s.passiveRequests.Load()
	if reqs == 0 {
		return 0
	}
	return float64(s.passiveErrors.Load()) / float64(reqs)
}

func (s *Score) SetConnHealth(health int32) {
	s.connHealth.Store(clamp(health, 0, 100))
}

func (s *Score) IsRapidDeterioration() bool {
	lastUpdate := s.LastUpdate()
	if time.Since(lastUpdate) > 5*time.Second {
		return false
	}

	return s.trend.Load() == -1 && s.value.Load() < 50
}

func clamp(v, min, max int32) int32 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
