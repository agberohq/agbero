package firewall

import (
	"time"

	"github.com/olekukonko/jack"
	"github.com/olekukonko/mappo"
)

type counterItem struct {
	count    int64
	expireAt time.Time
}

type Counters struct {
	data      *mappo.Sharded[string, *counterItem]
	scheduler *jack.Scheduler
}

func NewCounters() *Counters {
	c := &Counters{
		data: mappo.NewSharded[string, *counterItem](),
	}

	// Use jack scheduler for cleanup
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

// internal/middleware/firewall/counters.go

func (c *Counters) Increment(ruleID, key string, window time.Duration) int64 {
	fullKey := ruleID + "|" + key
	now := time.Now()

	item := c.data.Compute(fullKey, func(curr *counterItem, exists bool) (*counterItem, bool) {
		if !exists || now.After(curr.expireAt) {
			return &counterItem{
				count:    1,
				expireAt: now.Add(window),
			}, true
		}
		// Create NEW item to be safe with CAS / concurrency
		// Modifying 'curr' in place is unsafe if other readers have it
		next := &counterItem{
			count:    curr.count + 1,
			expireAt: curr.expireAt,
		}
		return next, true
	})

	return item.count
}

func (c *Counters) cleanup() {
	now := time.Now()
	c.data.ClearIf(func(k string, v *counterItem) bool {
		return now.After(v.expireAt)
	})
}
