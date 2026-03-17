package lb

import (
	"math"
	"net/http"

	"github.com/agberohq/agbero/internal/core/zulu"
)

// Adaptive load balancer wrapper.
// Leverages Backend's native atomic metrics (ResponseTime, InFlight) for
// lock-free, zero-allocation routing decisions using epsilon-greedy strategy.
type Adaptive struct {
	balancer     Balancer
	learningRate float64
}

// NewAdaptive creates a lock-free adaptive load balancer.
// learningRate controls exploration probability (0-1). Clamped to 0.15 if invalid.
func NewAdaptive(child Balancer, learningRate float64) *Adaptive {
	if learningRate < 0 || learningRate > 1 {
		learningRate = 0.15
	}
	return &Adaptive{
		balancer:     child,
		learningRate: learningRate,
	}
}

func (s *Adaptive) Update(backends []Backend) {
	s.balancer.Update(backends)
}

func (s *Adaptive) Backends() []Backend {
	return s.balancer.Backends()
}

func (s *Adaptive) Stop() {
	if s.balancer != nil {
		s.balancer.Stop()
	}
}

func (s *Adaptive) Pick(r *http.Request, keyFunc func() uint64) Backend {
	backends := s.balancer.Backends()
	n := len(backends)
	if n == 0 {
		return nil
	}

	// Epsilon-greedy: explore via base strategy
	rng := zulu.Rand()
	explore := rng.Float64() < s.learningRate
	zulu.RandPut(rng)

	if explore {
		return s.balancer.Pick(r, keyFunc)
	}

	if n == 1 {
		if backends[0].IsUsable() {
			return backends[0]
		}
		return nil
	}

	var best Backend
	bestScore := math.MaxFloat64

	for _, b := range backends {
		if !b.IsUsable() {
			continue
		}

		rt := float64(b.ResponseTime())
		if rt <= 0 {
			rt = 1000.0
		}
		inflight := float64(b.InFlight())

		// Score: lower is better. Penalizes high latency and high concurrency.
		score := rt * (1.0 + inflight*0.1)

		if score < bestScore {
			bestScore = score
			best = b
		}
	}

	if best != nil {
		return best
	}

	return s.balancer.Pick(r, keyFunc)
}

// Unwrap returns the underlying balancer for chain inspection.
func (s *Adaptive) Unwrap() Balancer {
	return s.balancer
}
