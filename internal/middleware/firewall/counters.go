package firewall

import (
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
)

const shardCount = 64

type counterItem struct {
	count    int64
	expireAt time.Time
}

type counterShard struct {
	mu    sync.Mutex
	items map[string]*counterItem
}

type Counters struct {
	shards [shardCount]*counterShard
	stop   chan struct{}
}

func NewCounters() *Counters {
	c := &Counters{
		stop: make(chan struct{}),
	}
	for i := 0; i < shardCount; i++ {
		c.shards[i] = &counterShard{
			items: make(map[string]*counterItem),
		}
	}
	go c.janitor()
	return c
}

func (c *Counters) Stop() {
	close(c.stop)
}

func (c *Counters) Increment(ruleID, key string, window time.Duration) int64 {
	fullKey := ruleID + "|" + key
	hash := xxhash.Sum64String(fullKey)
	shard := c.shards[hash%shardCount]

	now := time.Now()

	shard.mu.Lock()
	defer shard.mu.Unlock()

	item, exists := shard.items[fullKey]
	if !exists || now.After(item.expireAt) {
		shard.items[fullKey] = &counterItem{
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
			now := time.Now()
			for _, shard := range c.shards {
				shard.mu.Lock()
				for k, v := range shard.items {
					if now.After(v.expireAt) {
						delete(shard.items, k)
					}
				}
				shard.mu.Unlock()
			}
		}
	}
}
