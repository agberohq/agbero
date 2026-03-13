package lb

import (
	"math"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/cespare/xxhash/v2"
)

type Selector struct {
	Strategy  Strategy
	rrCounter atomic.Uint64

	mu       sync.RWMutex
	wheel    *WeightWheel
	backends []Backend
	ring     *Consistent
}

func NewSelector(backends []Backend, strategy Strategy) *Selector {
	s := &Selector{
		Strategy: strategy,
		backends: make([]Backend, len(backends)),
	}
	copy(s.backends, backends)

	weights := make([]int, len(backends))
	for i, b := range backends {
		weights[i] = b.Weight()
	}
	s.wheel = NewWheel(weights)

	if strategy == StrategyConsistentHash {
		s.ring = NewConsistent(len(backends), 150)
	}

	return s
}

func (s *Selector) Update(backends []Backend) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.backends = make([]Backend, len(backends))
	copy(s.backends, backends)

	weights := make([]int, len(backends))
	for i, b := range backends {
		weights[i] = b.Weight()
	}
	s.wheel = NewWheel(weights)

	if s.Strategy == StrategyConsistentHash {
		s.ring = NewConsistent(len(backends), 150)
	}
}

func (s *Selector) Backends() []Backend {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Backend, len(s.backends))
	copy(result, s.backends)
	return result
}

func (s *Selector) Pick(r *http.Request, keyFunc func() uint64) Backend {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.backends) == 0 {
		return nil
	}
	if len(s.backends) == 1 {
		if s.backends[0].IsUsable() {
			return s.backends[0]
		}
		return nil
	}

	switch s.Strategy {
	case StrategyRandom:
		return s.pickRandom()
	case StrategyLeastConn:
		return s.pickLeastConn()
	case StrategyWeightedLeastConn:
		return s.pickWeightedLeastConn()
	case StrategyIPHash:
		return s.pickIPHash(r)
	case StrategyURLHash:
		return s.pickURLHash(r)
	case StrategyLeastResponseTime:
		return s.pickLeastResponseTime()
	case StrategyPowerOfTwoChoices:
		return s.pickPowerOfTwoChoices()
	case StrategyConsistentHash:
		return s.pickConsistentHash(keyFunc())
	default:
		return s.pickRoundRobin()
	}
}

func (s *Selector) pickRoundRobin() Backend {
	n := len(s.backends)
	if n == 0 {
		return nil
	}

	for range n {
		counter := s.rrCounter.Add(1)
		var idx int

		if s.wheel != nil && len(s.wheel.cumul) > 0 {
			idx = s.wheel.Next(counter)
		} else {
			idx = int(counter % uint64(n))
		}

		if idx < n && s.backends[idx].IsUsable() {
			return s.backends[idx]
		}
	}
	return nil
}

func (s *Selector) pickRandom() Backend {
	n := len(s.backends)
	if n == 0 {
		return nil
	}

	rng := zulu.Rand()
	defer zulu.RandPut(rng)

	start := rng.IntN(n)
	for i := range n {
		idx := (start + i) % n
		if s.backends[idx].IsUsable() {
			return s.backends[idx]
		}
	}
	return nil
}

func (s *Selector) pickLeastConn() Backend {
	var best Backend
	min := int64(math.MaxInt64)

	for _, b := range s.backends {
		if !b.IsUsable() {
			continue
		}
		if c := b.InFlight(); c < min {
			min = c
			best = b
		}
	}
	return best
}

func (s *Selector) pickWeightedLeastConn() Backend {
	var best Backend
	bestRatio := -1.0

	for _, b := range s.backends {
		if !b.IsUsable() {
			continue
		}

		w := float64(b.Weight())
		if w <= 0 {
			w = 1
		}
		c := float64(b.InFlight() + 1)
		ratio := c / w

		if bestRatio < 0 || ratio < bestRatio {
			best = b
			bestRatio = ratio
		}
	}
	return best
}

func (s *Selector) pickIPHash(r *http.Request) Backend {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	key := xxhash.Sum64String(host)
	return s.pickHash(key)
}

func (s *Selector) pickURLHash(r *http.Request) Backend {
	key := xxhash.Sum64String(r.URL.Path)
	return s.pickHash(key)
}

func (s *Selector) pickHash(key uint64) Backend {
	if key == 0 || s.wheel == nil || s.wheel.total == 0 {
		return s.pickRandom()
	}

	idx := s.wheel.search(key % s.wheel.total)
	if idx >= 0 && idx < len(s.backends) && s.backends[idx].IsUsable() {
		return s.backends[idx]
	}
	return s.pickRandom()
}

func (s *Selector) pickLeastResponseTime() Backend {
	var best Backend
	bestScore := float64(math.MaxFloat64)

	for _, b := range s.backends {
		if !b.IsUsable() {
			continue
		}

		responseTime := float64(b.ResponseTime())
		if responseTime <= 0 {
			responseTime = 1000
		}
		inflight := float64(b.InFlight())

		score := responseTime * (1 + inflight*0.1)

		if score < bestScore {
			bestScore = score
			best = b
		}
	}
	return best
}

func (s *Selector) pickPowerOfTwoChoices() Backend {
	n := len(s.backends)
	if n == 0 {
		return nil
	}
	if n < 2 {
		return s.pickLeastConn()
	}

	rng := zulu.Rand()
	defer zulu.RandPut(rng)

	idx1 := rng.IntN(n)
	idx2 := rng.IntN(n - 1)
	if idx2 >= idx1 {
		idx2++
	}

	var candidates []int
	if idx1 < n && s.backends[idx1].IsUsable() {
		candidates = append(candidates, idx1)
	}
	if idx2 < n && s.backends[idx2].IsUsable() {
		candidates = append(candidates, idx2)
	}

	if len(candidates) == 0 {
		return s.pickLeastConn()
	}
	if len(candidates) == 1 {
		return s.backends[candidates[0]]
	}

	if s.backends[candidates[0]].InFlight() < s.backends[candidates[1]].InFlight() {
		return s.backends[candidates[0]]
	}
	return s.backends[candidates[1]]
}

func (s *Selector) pickConsistentHash(key uint64) Backend {
	if s.ring == nil || len(s.ring.ring) == 0 {
		return s.pickRandom()
	}

	h := HashUint64(key)
	idx := s.ring.Get(h)
	if idx < 0 || idx >= len(s.backends) {
		return s.pickRandom()
	}

	for i := 0; i < len(s.backends); i++ {
		checkIdx := (idx + i) % len(s.backends)
		if s.backends[checkIdx].IsUsable() {
			return s.backends[checkIdx]
		}
	}
	return nil
}

func (s *Selector) Stop() {
	s.mu.Lock()
	s.backends = nil
	s.mu.Unlock()
}
