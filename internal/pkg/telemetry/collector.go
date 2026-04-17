package telemetry

import (
	"context"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/olekukonko/ll"
)

// Collector scrapes the live uptime data on a fixed interval and
// persists samples to the Store.  It is deliberately decoupled from
// the HTTP layer — no allocations happen on the request path.
type Collector struct {
	store       *Store
	hostManager *discovery.Host
	res         *resource.Resource
	logger      *ll.Logger

	mu        sync.Mutex
	prevState map[string]*prevState // keyed by host domain

	quit chan struct{}
	done chan struct{}
}

// NewCollector wires up the collector. Call Start() to begin sampling.
func NewCollector(
	store *Store,
	hm *discovery.Host,
	res *resource.Resource,
	logger *ll.Logger,
) *Collector {
	return &Collector{
		store:       store,
		hostManager: hm,
		res:         res,
		logger:      logger.Namespace("telemetry"),
		prevState:   make(map[string]*prevState),
		quit:        make(chan struct{}),
		done:        make(chan struct{}),
	}
}

// Start launches the background sampling goroutine.
// It samples immediately on start, then every CollectInterval.
func (c *Collector) Start() {
	go func() {
		defer close(c.done)
		c.collect() // immediate first sample
		ticker := time.NewTicker(CollectInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.collect()
			case <-c.quit:
				return
			}
		}
	}()
}

// Stop signals the collector to exit and waits for it to finish.
func (c *Collector) Stop() {
	close(c.quit)
	<-c.done
}

// collect takes one snapshot across all known hosts and records it.
func (c *Collector) collect() {
	hosts, err := c.hostManager.LoadAll()
	if err != nil {
		c.logger.Fields("err", err).Error("telemetry: failed to load hosts")
		return
	}

	now := time.Now()

	for domain, hcfg := range hosts {
		var (
			totalReqs   uint64
			totalErrors uint64
			sumP99      float64
			countP99    int
			activeBE    int
		)

		for _, route := range hcfg.Routes {
			for _, srv := range route.Backends.Servers {
				statsKey := route.KeyBackend(domain, srv.Address.String())
				stats := c.res.Metrics.Get(statsKey)
				if stats == nil {
					continue
				}
				snap := stats.Activity.Snapshot()

				reqs, _ := snap["requests"].(uint64)
				fails, _ := snap["failures"].(uint64)
				totalReqs += reqs
				totalErrors += fails

				if latSnap, ok := snap["latency"].(interface {
					P99() int64
					Count() uint64
				}); ok && latSnap.Count() > 0 {
					sumP99 += float64(latSnap.P99()) / 1000.0 // µs → ms
					countP99++
				}

				// Check liveness via health registry
				if hScore, ok := c.res.Health.Get(statsKey); ok {
					if hScore.State().String() != "Dead" && hScore.State().String() != "Unhealthy" {
						activeBE++
					}
				}
			}
		}

		// Compute deltas for req/s and error rate
		c.mu.Lock()
		prev := c.prevState[domain]

		var reqsSec float64
		var errorRate float64

		if prev != nil && now.After(prev.capturedAt) {
			elapsed := now.Sub(prev.capturedAt).Seconds()
			if elapsed > 0 {
				deltaReqs := float64(totalReqs) - float64(prev.totalReqs)
				if deltaReqs < 0 {
					deltaReqs = 0 // counter reset (restart)
				}
				reqsSec = deltaReqs / elapsed
			}
			if totalReqs > prev.totalReqs {
				deltaReqs := totalReqs - prev.totalReqs
				deltaErrors := totalErrors - prev.totalErrors
				if deltaReqs > 0 {
					errorRate = float64(deltaErrors) / float64(deltaReqs) * 100.0
				}
			}
		}

		c.prevState[domain] = &prevState{
			totalReqs:   totalReqs,
			totalErrors: totalErrors,
			capturedAt:  now,
		}
		c.mu.Unlock()

		var p99 float64
		if countP99 > 0 {
			p99 = sumP99 / float64(countP99)
		}

		sample := Sample{
			Timestamp:   now.Unix(),
			RequestsSec: reqsSec,
			P99Ms:       p99,
			ErrorRate:   errorRate,
			ActiveBE:    activeBE,
		}

		c.store.Record(domain, sample)
	}

	ctx := context.Background()
	_ = ctx // reserved for future use
}
