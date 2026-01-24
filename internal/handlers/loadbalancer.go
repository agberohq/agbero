package handlers

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/backend"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

type LoadBalancerHandler struct {
	stripPrefixes []string
	strategy      string
	Backends      []*backend.Backend
	rrCounter     uint64
	timeout       time.Duration
}

func (lb *LoadBalancerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(lb.Backends) == 0 {
		http.Error(w, "No backends configured", http.StatusBadGateway)
		return
	}

	b := lb.PickBackend()
	if b == nil {
		http.Error(w, "No healthy backends", http.StatusBadGateway)
		return
	}

	// Apply Route Timeout
	if lb.timeout > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), lb.timeout)
		defer cancel()
		r = r.WithContext(ctx)
		b.ServeHTTP(w, r)
	} else {
		b.ServeHTTP(w, r)
	}
}

func (lb *LoadBalancerHandler) PickBackend() *backend.Backend {
	if len(lb.Backends) == 1 {
		b := lb.Backends[0]
		if b.Alive.Load() {
			return b
		}
		return nil
	}

	switch lb.strategy {
	case alaye.StrategyLeastConn:
		return lb.pickLeastConn()
	case alaye.StrategyRandom:
		return lb.pickRandom()
	default:
		return lb.pickRoundRobin()
	}
}

func (lb *LoadBalancerHandler) pickRoundRobin() *backend.Backend {
	n := uint64(len(lb.Backends))
	for i := uint64(0); i < n; i++ {
		idx := atomic.AddUint64(&lb.rrCounter, 1)
		b := lb.Backends[idx%n]
		if b.Alive.Load() {
			return b
		}
	}
	return nil
}

func (lb *LoadBalancerHandler) pickRandom() *backend.Backend {
	n := len(lb.Backends)
	start := randUint64()
	for i := 0; i < n; i++ {
		idx := (start + uint64(i)) % uint64(n)
		b := lb.Backends[idx]
		if b.Alive.Load() {
			return b
		}
	}
	return nil
}

func (lb *LoadBalancerHandler) pickLeastConn() *backend.Backend {
	var (
		best *backend.Backend
		min  int64 = -1
	)

	// To avoid stampeding the first backend when all have 0 conns,
	// start iteration at a random offset
	n := len(lb.Backends)
	start := int(randUint64() % uint64(n))

	for i := 0; i < n; i++ {
		idx := (start + i) % n
		b := lb.Backends[idx]

		if !b.Alive.Load() {
			continue
		}
		c := b.InFlight.Load()
		if min == -1 || c < min {
			min = c
			best = b
		}
	}
	return best
}
