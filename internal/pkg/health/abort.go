package health

import (
	"sync/atomic"

	"github.com/agberohq/agbero/internal/core/alaye"
)

type EarlyAbortController struct {
	enabled    atomic.Bool
	abortCh    chan alaye.BackendKey // backend ID to abort
	threshold  int32                 // score drop threshold
	windowSecs int32
}

func NewEarlyAbortController(enabled bool) *EarlyAbortController {
	eac := &EarlyAbortController{
		abortCh:    make(chan alaye.BackendKey, 100),
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

func (eac *EarlyAbortController) ShouldAbort(backendKey alaye.BackendKey, score *Score) bool {
	if !eac.enabled.Load() {
		return false
	}

	// Check rapid deterioration
	if score.IsRapidDeterioration() {
		select {
		case eac.abortCh <- backendKey:
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

func (eac *EarlyAbortController) AbortChannel() <-chan alaye.BackendKey {
	return eac.abortCh
}
