package tcp

import (
	"math"
	"math/rand"
	"strings"
	"sync/atomic"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

type Balancer struct {
	backends []*Backend
	strategy uint8

	rrCounter atomic.Uint64
}

func NewBalancer(cfg alaye.TCPRoute) *Balancer {
	var backends []*Backend

	hcInterval := woos.TCPHealthCheckInterval
	hcTimeout := woos.TCPHealthCheckTimeout
	failThresh := int64(2)

	for _, b := range cfg.Backends {
		w := b.Weight
		if w <= 0 {
			w = 1
		}
		be := &Backend{
			Address:    b.Address,
			Weight:     w,
			hcInterval: hcInterval,
			hcTimeout:  hcTimeout,
			failThresh: failThresh,
			stop:       make(chan struct{}),
		}
		be.Alive.Store(true)
		go be.healthCheckLoop()
		backends = append(backends, be)
	}

	strat := woos.StRoundRobin
	switch strings.ToLower(strings.TrimSpace(cfg.Strategy)) {
	case "least_conn":
		strat = woos.StLeastConn
	case "random":
		strat = woos.StRandom
	}

	return &Balancer{
		backends: backends,
		strategy: uint8(strat),
	}
}

func (tb *Balancer) Stop() {
	for _, b := range tb.backends {
		if b != nil {
			b.Stop()
		}
	}
}

func (tb *Balancer) BackendCount() int { return len(tb.backends) }

func (tb *Balancer) Pick(exclude map[*Backend]struct{}) *Backend {
	if len(tb.backends) == 0 {
		return nil
	}
	// Optimization for single backend
	if len(tb.backends) == 1 {
		b := tb.backends[0]
		if b != nil && b.Alive.Load() {
			if _, ok := exclude[b]; !ok {
				return b
			}
		}
		return nil
	}

	switch tb.strategy {
	case woos.StLeastConn:
		return tb.pickLeastConn(exclude)
	case woos.StRandom:
		return tb.pickRandom(exclude)
	default:
		return tb.pickRoundRobin(exclude)
	}
}

func (tb *Balancer) pickRoundRobin(exclude map[*Backend]struct{}) *Backend {
	n := uint64(len(tb.backends))
	start := tb.rrCounter.Add(1)

	for i := 0; i < len(tb.backends); i++ {
		idx := int((start + uint64(i)) % n)
		b := tb.backends[idx]
		if b == nil || !b.Alive.Load() {
			continue
		}
		if _, ok := exclude[b]; ok {
			continue
		}
		return b
	}
	return nil
}

func (tb *Balancer) pickRandom(exclude map[*Backend]struct{}) *Backend {
	r := rngPool.Get().(*rand.Rand)
	start := r.Intn(len(tb.backends))
	rngPool.Put(r)

	n := len(tb.backends)
	// Random start, sequential scan (avoids infinite loops if all excluded)
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		b := tb.backends[idx]
		if b == nil || !b.Alive.Load() {
			continue
		}
		if _, ok := exclude[b]; ok {
			continue
		}
		return b
	}
	return nil
}

func (tb *Balancer) pickLeastConn(exclude map[*Backend]struct{}) *Backend {
	var best *Backend
	min := int64(math.MaxInt64)

	for _, b := range tb.backends {
		if b == nil || !b.Alive.Load() {
			continue
		}
		if _, ok := exclude[b]; ok {
			continue
		}
		c := b.ActiveConns.Load()
		if c < min {
			min = c
			best = b
		}
	}
	return best
}
