package health

import (
	"sync/atomic"
)

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
