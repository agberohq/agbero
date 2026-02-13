package metrics

import (
	"sync/atomic"
	"time"
)

type Health struct {
	healthy             atomic.Bool
	consecutiveFailures atomic.Int64
	totalChecks         atomic.Uint64
	totalFailures       atomic.Uint64
	lastFailure         atomic.Int64
	lastSuccess         atomic.Int64
}

func NewHealthTracker() *Health {
	ht := &Health{}
	ht.healthy.Store(true)
	return ht
}

func (ht *Health) RecordSuccess() {
	now := time.Now().UnixNano()
	ht.lastSuccess.Store(now)
	ht.consecutiveFailures.Store(0)
	ht.healthy.Store(true)
	ht.totalChecks.Add(1)
}

func (ht *Health) RecordFailure() {
	now := time.Now().UnixNano()
	ht.lastFailure.Store(now)
	ht.consecutiveFailures.Add(1)
	ht.totalChecks.Add(1)
	ht.totalFailures.Add(1)
}

func (ht *Health) IsHealthy() bool {
	return ht.healthy.Load()
}

func (ht *Health) ConsecutiveFailures() int64 {
	return ht.consecutiveFailures.Load()
}

func (ht *Health) LastSuccess() time.Time {
	return time.Unix(0, ht.lastSuccess.Load())
}

func (ht *Health) LastFailure() time.Time {
	return time.Unix(0, ht.lastFailure.Load())
}

func (ht *Health) TotalChecks() uint64 {
	return ht.totalChecks.Load()
}

func (ht *Health) TotalFailures() uint64 {
	return ht.totalFailures.Load()
}
