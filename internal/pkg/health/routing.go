package health

import (
	"sync/atomic"
	"time"
)

type RoutingWeights struct {
	DegradedMultiplier  float64
	UnhealthyMultiplier float64
	DrainTimeout        int64 // nanoseconds
	EarlyAbortEnabled   bool
}

func DefaultRoutingWeights() RoutingWeights {
	return RoutingWeights{
		DegradedMultiplier:  0.5,
		UnhealthyMultiplier: 0.1,
		DrainTimeout:        int64(30 * time.Second),
		EarlyAbortEnabled:   true,
	}
}

func (rw *RoutingWeights) EffectiveWeight(configuredWeight int, score *Score) int {
	if configuredWeight <= 0 {
		configuredWeight = 1
	}

	state := score.State()
	baseScore := float64(score.Value()) / 100.0

	switch state {
	case StateHealthy:
		return int(float64(configuredWeight) * baseScore)

	case StateDegraded:
		healthWeight := float64(configuredWeight) * baseScore
		return int(healthWeight * rw.DegradedMultiplier)

	case StateUnhealthy:
		healthWeight := float64(configuredWeight) * baseScore
		return int(healthWeight * rw.UnhealthyMultiplier)

	case StateDead:
		return 0
	}

	return 0
}

type EarlyAbortController struct {
	enabled    atomic.Bool
	abortCh    chan string // backend ID to abort
	threshold  int32       // score drop threshold
	windowSecs int32
}

func NewEarlyAbortController(enabled bool) *EarlyAbortController {
	eac := &EarlyAbortController{
		abortCh:    make(chan string, 100),
		threshold:  30,
		windowSecs: 5,
	}
	eac.enabled.Store(enabled)
	return eac
}

func (eac *EarlyAbortController) Enable() {
	eac.enabled.Store(true)
}

func (eac *EarlyAbortController) Disable() {
	eac.enabled.Store(false)
}

func (eac *EarlyAbortController) ShouldAbort(backendID string, score *Score) bool {
	if !eac.enabled.Load() {
		return false
	}

	// Check rapid deterioration
	if score.IsRapidDeterioration() {
		select {
		case eac.abortCh <- backendID:
		default:
		}
		return true
	}

	// Check unhealthy state
	if score.State() == StateUnhealthy {
		return true
	}

	return false
}

func (eac *EarlyAbortController) AbortChannel() <-chan string {
	return eac.abortCh
}
