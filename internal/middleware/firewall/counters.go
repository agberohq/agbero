package firewall

import (
	"time"

	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/mappo"
)

const (
	counterShardCount = 64
	counterCleanupInt = 1 * time.Minute
	counterGCRoutine  = "fw-counters-gc"
	counterGCPool     = 1
	counterIncrement  = 1
)

var counterBits = []uint8{40, 24}

type atomicCounter struct {
	state zulu.AtomicPacked
}

type Counters struct {
	data      *mappo.Sharded[string, *atomicCounter]
	scheduler *jack.Scheduler
}

// NewCounters initializes the rate limit tracking map and garbage collector
// Ensures bounded memory usage by sweeping expired records periodically
func NewCounters() *Counters {
	c := &Counters{
		data: mappo.NewShardedWithConfig[string, *atomicCounter](mappo.ShardedConfig{ShardCount: counterShardCount}),
	}

	sched, _ := jack.NewScheduler(counterGCRoutine, jack.NewPool(counterGCPool), jack.Routine{
		Interval: counterCleanupInt,
	})
	_ = sched.Do(jack.Do(c.cleanup))
	c.scheduler = sched

	return c
}

// Stop terminates the background cleanup scheduler safely
// Clears all map data to prevent memory leaks during hot reloads
func (c *Counters) Stop() {
	if c.scheduler != nil {
		_ = c.scheduler.Stop()
	}
	c.data.Clear()
}

// Increment safely adds to the key counter using a lock-free compare-and-swap loop
// Automatically evicts expired timestamps and begins a new rate-limit window
func (c *Counters) Increment(ruleID, key string, window time.Duration) int64 {
	fullKey := ruleID + "|" + key
	nowSec := time.Now().Unix()
	expireSec := nowSec + int64(window.Seconds())

	var result int64

	c.data.Compute(fullKey, func(curr *atomicCounter, exists bool) (*atomicCounter, bool) {
		if !exists {
			newCounter := &atomicCounter{}
			newCounter.state.Store(zulu.NewPacked(counterBits, expireSec, counterIncrement))
			result = counterIncrement
			return newCounter, true
		}

		for {
			oldPacked := curr.state.Load()
			values := oldPacked.Extract(counterBits)
			oldExpire, oldCount := values[0], values[1]

			if nowSec > oldExpire {
				newPacked := zulu.NewPacked(counterBits, expireSec, counterIncrement)
				if curr.state.CompareAndSwap(oldPacked, newPacked) {
					result = counterIncrement
					return curr, true
				}
				continue
			}

			newPacked := zulu.NewPacked(counterBits, oldExpire, oldCount+counterIncrement)
			if curr.state.CompareAndSwap(oldPacked, newPacked) {
				result = oldCount + counterIncrement
				return curr, true
			}
		}
	})

	return result
}

// cleanup removes stale entries from the tracking map
// Executed by the background scheduler to maintain optimal memory consumption
func (c *Counters) cleanup() {
	now := time.Now().Unix()
	c.data.ClearIf(func(k string, v *atomicCounter) bool {
		values := v.state.Load().Extract(counterBits)
		expireAt := values[0]
		return now > expireAt
	})
}
