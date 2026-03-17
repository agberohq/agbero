// internal/pkg/health/abort.go
package health

import (
	"sync/atomic"
)

const (
	defaultScoreThreshold = 30
	defaultWindowSecs     = 5
)

type EarlyAbortController struct {
	enabled    atomic.Bool
	threshold  int32
	windowSecs int32
}

// NewEarlyAbortController constructs a controller for preemptive traffic shedding.
// Drops traffic safely based on health telemetry without background channel monitors.
func NewEarlyAbortController(enabled bool) *EarlyAbortController {
	eac := &EarlyAbortController{
		threshold:  defaultScoreThreshold,
		windowSecs: defaultWindowSecs,
	}
	eac.enabled.Store(enabled)
	return eac
}

// Enable activates the early abort circuit breaker mechanism globally.
// Restores rapid deterioration checks for all configured routing backends.
func (eac *EarlyAbortController) Enable() {
	eac.enabled.Store(true)
}

// Disable deactivates the early abort circuit breaker mechanism globally.
// Permits traffic to flow regardless of rapid deterioration telemetry.
func (eac *EarlyAbortController) Disable() {
	eac.enabled.Store(false)
}

// ShouldAbort evaluates if traffic should be preemptively dropped before dialing.
// Halts execution if the backend shows rapid deterioration or prolonged instability.
func (eac *EarlyAbortController) ShouldAbort(score *Score) bool {
	if !eac.enabled.Load() {
		return false
	}

	if score.IsRapidDeterioration() {
		return true
	}

	if score.State() == StateUnhealthy {
		return true
	}

	return false
}
