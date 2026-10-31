package telemetry

import (
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/pkg/metrics"
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

// collect takes one snapshot across all registered backends and records it.
//
// It deliberately reads the metrics registry rather than the host configuration:
// walking `HostManager.LoadAll()` raced with the code that applies route defaults
// (woos.defaultBackend mutating Backends.Servers[i].Weight inside a published
// route), which the race detector flagged at startup. The registry is the
// canonical, lock-free list of backends and needs no config access at all.
func (c *Collector) collect() {
	targets := c.res.Metrics.Snapshot()
	if len(targets) == 0 {
		return
	}

	now := time.Now()

	// Aggregate per domain across every route/backend registered for it.
	type agg struct {
		totalReqs   uint64
		totalErrors uint64
		sumP99      float64
		countP99    int
		activeBE    int
	}
	domains := make(map[string]*agg)

	for key, stats := range targets {
		if stats == nil || stats.Activity == nil {
			continue
		}
		domain := key.Domain
		if domain == "" {
			domain = "*"
		}
		a := domains[domain]
		if a == nil {
			a = &agg{}
			domains[domain] = a
		}

		snap := stats.Activity.Snapshot()

		reqs, _ := snap["requests"].(uint64)
		fails, _ := snap["failures"].(uint64)
		a.totalReqs += reqs
		a.totalErrors += fails

		if latSnap, ok := snap["latency"].(metrics.LatencySnapshot); ok && latSnap.Count > 0 {
			a.sumP99 += float64(latSnap.P99) / 1000.0 // µs → ms
			a.countP99++
		}

		if hScore, ok := c.res.Health.Get(key); ok {
			if state := hScore.State().String(); state != "Dead" && state != "Unhealthy" {
				a.activeBE++
			}
		}
	}

	for domain, a := range domains {
		// Compute deltas for req/s and error rate
		c.mu.Lock()
		prev := c.prevState[domain]

		var reqsSec float64
		var errorRate float64

		if prev != nil && now.After(prev.capturedAt) {
			elapsed := now.Sub(prev.capturedAt).Seconds()
			if elapsed > 0 {
				deltaReqs := float64(a.totalReqs) - float64(prev.totalReqs)
				if deltaReqs < 0 {
					deltaReqs = 0 // counter reset (restart)
				}
				reqsSec = deltaReqs / elapsed
			}
			if a.totalReqs > prev.totalReqs {
				deltaReqs := a.totalReqs - prev.totalReqs
				deltaErrors := a.totalErrors - prev.totalErrors
				if deltaReqs > 0 {
					errorRate = float64(deltaErrors) / float64(deltaReqs) * 100.0
				}
			}
		}

		c.prevState[domain] = &prevState{
			totalReqs:   a.totalReqs,
			totalErrors: a.totalErrors,
			capturedAt:  now,
		}
		c.mu.Unlock()

		var p99 float64
		if a.countP99 > 0 {
			p99 = a.sumP99 / float64(a.countP99)
		}

		c.store.Record(domain, Sample{
			Timestamp:   now.Unix(),
			RequestsSec: reqsSec,
			P99Ms:       p99,
			ErrorRate:   errorRate,
			ActiveBE:    a.activeBE,
		})
	}
}
