package handlers

import (
	"context"
	"crypto/rand"
	"math/big"
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
	totalWeight   uint64 // Pre-calculated sum of weights
}

// RecalculateTotalWeight should be called during init
func (lb *LoadBalancerHandler) recalculateTotalWeight() {
	var sum uint64
	for _, b := range lb.Backends {
		w := b.Weight
		if w <= 0 {
			w = 1
		}
		sum += uint64(w)
	}
	lb.totalWeight = sum
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
		// If weights are uniform (all 1), use simple random
		if lb.totalWeight == uint64(len(lb.Backends)) {
			return lb.pickRandom()
		}
		return lb.pickWeightedRandom()
	default: // Round Robin
		// If weights are uniform, use simple RR
		if lb.totalWeight == uint64(len(lb.Backends)) {
			return lb.pickRoundRobin()
		}
		return lb.pickWeightedRoundRobin()
	}
}

// Simple Round Robin (Uniform Weights)
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

// Weighted Round Robin
// Iterates based on cumulative weight.
// A(3), B(1). Total 4.
// Counter 0 -> A, 1 -> A, 2 -> A, 3 -> B
func (lb *LoadBalancerHandler) pickWeightedRoundRobin() *backend.Backend {
	total := lb.totalWeight
	if total == 0 {
		return lb.pickRoundRobin()
	}

	// Try up to len(Backends) times to find a healthy one to avoid infinite loops
	// if the weighting logic keeps landing on a dead node.
	attempts := len(lb.Backends)

	// Atomic increment
	current := atomic.AddUint64(&lb.rrCounter, 1)

	for i := 0; i < attempts; i++ {
		// Determine target within the weight window
		target := (current + uint64(i)) % total

		var cursor uint64
		for _, b := range lb.Backends {
			w := uint64(b.Weight)
			if w <= 0 {
				w = 1
			}

			cursor += w
			// If target falls in this backend's range
			if target < cursor {
				if b.Alive.Load() {
					return b
				}
				// If dead, break inner loop to increment attempt and try "next" slot
				break
			}
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

// Weighted Random
func (lb *LoadBalancerHandler) pickWeightedRandom() *backend.Backend {
	total := lb.totalWeight
	if total == 0 {
		return lb.pickRandom()
	}

	// Generate random number [0, total)
	rNum, err := rand.Int(rand.Reader, big.NewInt(int64(total)))
	if err != nil {
		return lb.pickRandom() // Fallback
	}
	target := rNum.Uint64()

	var cursor uint64
	// Simple linear scan O(N) - N is small (backends)
	for _, b := range lb.Backends {
		w := uint64(b.Weight)
		if w <= 0 {
			w = 1
		}
		cursor += w

		if target < cursor {
			if b.Alive.Load() {
				return b
			}
			// If selected is dead, fallback to simple random to find *something* alive quickly
			return lb.pickRandom()
		}
	}
	return nil
}

func (lb *LoadBalancerHandler) pickLeastConn() *backend.Backend {
	var (
		best *backend.Backend
		min  int64 = -1
	)

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

// Helper needed because we changed handlers package but forgot to add initialization
// in routes.go to call recalculateTotalWeight.
// We should update handlers/routes.go to set this up.
