package firewall

import (
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/mappo"
)

// Bit layout: [32 bits count | 32 bits expire timestamp]
var counterBits = []uint8{32, 32}

type atomicCounter struct {
	state zulu.AtomicPacked
}

type Counters struct {
	data      *mappo.Sharded[string, *atomicCounter]
	scheduler *jack.Scheduler
}

func NewCounters() *Counters {
	c := &Counters{
		data: mappo.NewShardedWithConfig[string, *atomicCounter](mappo.ShardedConfig{ShardCount: 64}),
	}

	sched, _ := jack.NewScheduler("fw-counters-gc", jack.NewPool(1), jack.Routine{
		Interval: 1 * time.Minute,
	})
	_ = sched.Do(jack.Do(c.cleanup))
	c.scheduler = sched

	return c
}

func (c *Counters) Stop() {
	if c.scheduler != nil {
		_ = c.scheduler.Stop()
	}
	c.data.Clear()
}

func (c *Counters) Increment(ruleID, key string, window time.Duration) int64 {
	fullKey := ruleID + "|" + key
	nowSec := time.Now().Unix()
	expireSec := nowSec + int64(window.Seconds())

	var result int64

	c.data.Compute(fullKey, func(curr *atomicCounter, exists bool) (*atomicCounter, bool) {
		if !exists {
			newCounter := &atomicCounter{}
			newCounter.state.Store(zulu.NewPacked(counterBits, expireSec, 1))
			result = 1
			return newCounter, true
		}

		// CAS loop for atomic update
		for {
			oldPacked := curr.state.Load()
			values := oldPacked.Extract(counterBits)
			oldExpire, oldCount := values[0], values[1]

			// Check expiration
			if nowSec > oldExpire {
				newPacked := zulu.NewPacked(counterBits, expireSec, 1)
				if curr.state.CompareAndSwap(oldPacked, newPacked) {
					result = 1
					return curr, true
				}
				continue
			}

			// Increment
			newPacked := zulu.NewPacked(counterBits, oldExpire, oldCount+1)
			if curr.state.CompareAndSwap(oldPacked, newPacked) {
				result = oldCount + 1
				return curr, true
			}
		}
	})

	return result
}

func (c *Counters) cleanup() {
	now := time.Now().Unix()
	c.data.ClearIf(func(k string, v *atomicCounter) bool {
		values := v.state.Load().Extract(counterBits)
		expireAt := values[0]
		return now > expireAt
	})
}
