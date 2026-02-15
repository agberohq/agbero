package firewall

import (
	"encoding/hex"
	"sync"
	"time"
)

type counterItem struct {
	count    int64
	expireAt time.Time
}

type Counters struct {
	mu    sync.Mutex
	items map[string]*counterItem
	stop  chan struct{}
}

func NewCounters() *Counters {
	c := &Counters{
		items: make(map[string]*counterItem),
		stop:  make(chan struct{}),
	}
	go c.janitor()
	return c
}

func (c *Counters) Stop() {
	close(c.stop)
}

func (c *Counters) Increment(ruleID, key string, window time.Duration) int64 {
	fullKey := ruleID + ":" + hex.EncodeToString([]byte(key))
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	item, exists := c.items[fullKey]
	if !exists || now.After(item.expireAt) {
		c.items[fullKey] = &counterItem{
			count:    1,
			expireAt: now.Add(window),
		}
		return 1
	}

	item.count++
	return item.count
}

func (c *Counters) janitor() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

func (c *Counters) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, v := range c.items {
		if now.After(v.expireAt) {
			delete(c.items, k)
		}
	}
}
