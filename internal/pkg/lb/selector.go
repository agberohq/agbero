package lb

import (
	"math"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/cespare/xxhash/v2"
)

type selectorState struct {
	backends []Backend
	wheel    *WeightWheel
	ring     *Consistent
}

type Selector struct {
	Strategy  Strategy
	rrCounter atomic.Uint64
	state     atomic.Pointer[selectorState]
}

func NewSelector(backends []Backend, strategy Strategy) *Selector {
	s := &Selector{Strategy: strategy}
	s.Update(backends)
	return s
}

func (s *Selector) Update(backends []Backend) {
	st := &selectorState{
		backends: make([]Backend, len(backends)),
	}
	copy(st.backends, backends)

	weights := make([]int, len(backends))
	for i, b := range backends {
		weights[i] = b.Weight()
	}
	st.wheel = NewWheel(weights)

	if s.Strategy == StrategyConsistentHash {
		st.ring = NewConsistent(len(backends), 150)
	}

	s.state.Store(st)
}

func (s *Selector) Backends() []Backend {
	st := s.state.Load()
	if st == nil {
		return nil
	}
	result := make([]Backend, len(st.backends))
	copy(result, st.backends)
	return result
}

func (s *Selector) Pick(r *http.Request, keyFunc func() uint64) Backend {
	st := s.state.Load()
	if st == nil || len(st.backends) == 0 {
		return nil
	}

	if len(st.backends) == 1 {
		if st.backends[0].IsUsable() {
			return st.backends[0]
		}
		return nil
	}

	switch s.Strategy {
	case StrategyRandom:
		return s.pickRandom(st)
	case StrategyLeastConn:
		return s.pickLeastConn(st)
	case StrategyWeightedLeastConn:
		return s.pickWeightedLeastConn(st)
	case StrategyIPHash:
		return s.pickIPHash(r, keyFunc, st)
	case StrategyURLHash:
		return s.pickURLHash(r, st)
	case StrategyLeastResponseTime:
		return s.pickLeastResponseTime(st)
	case StrategyPowerOfTwoChoices:
		return s.pickPowerOfTwoChoices(st)
	case StrategyConsistentHash:
		return s.pickConsistentHash(keyFunc(), st)
	default:
		return s.pickRoundRobin(st)
	}
}

func (s *Selector) pickRoundRobin(st *selectorState) Backend {
	n := len(st.backends)
	// Power-of-2 optimization: use bitwise AND instead of modulo when possible
	// This avoids expensive division when backend count is 2,4,8,16,32,64,128...
	isPow2 := n > 0 && (n&(n-1)) == 0
	mask := uint64(n - 1)

	for range n {
		counter := s.rrCounter.Add(1)
		var idx int
		if st.wheel != nil && st.wheel.total > 0 {
			idx = st.wheel.Next(counter)
		} else if isPow2 {
			// Faster: counter & (n-1) instead of counter % n
			// Saves ~8-15 CPU cycles per Pick() on ARM64
			idx = int(counter & mask)
		} else {
			idx = int(counter % uint64(n))
		}
		if idx < n && st.backends[idx].IsUsable() {
			return st.backends[idx]
		}
	}
	return nil
}

func (s *Selector) pickRandom(st *selectorState) Backend {
	n := len(st.backends)
	rng := zulu.Rand()
	defer zulu.RandPut(rng)

	start := rng.IntN(n)
	for i := range n {
		idx := (start + i) % n
		if st.backends[idx].IsUsable() {
			return st.backends[idx]
		}
	}
	return nil
}

func (s *Selector) pickLeastConn(st *selectorState) Backend {
	var best Backend
	min := int64(math.MaxInt64)
	for _, b := range st.backends {
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

func (s *Selector) pickWeightedLeastConn(st *selectorState) Backend {
	var best Backend
	bestRatio := -1.0
	for _, b := range st.backends {
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

func (s *Selector) pickIPHash(r *http.Request, keyFunc func() uint64, st *selectorState) Backend {
	var key uint64
	if keyFunc != nil {
		key = keyFunc()
	} else {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		key = xxhash.Sum64String(host)
	}
	return s.pickHash(key, st)
}

func (s *Selector) pickURLHash(r *http.Request, st *selectorState) Backend {
	key := xxhash.Sum64String(r.URL.Path)
	return s.pickHash(key, st)
}

func (s *Selector) pickHash(key uint64, st *selectorState) Backend {
	if key == 0 || st.wheel == nil || st.wheel.total == 0 {
		return s.pickRandom(st)
	}
	idx := st.wheel.Next(key % st.wheel.total)
	if idx >= 0 && idx < len(st.backends) && st.backends[idx].IsUsable() {
		return st.backends[idx]
	}
	return s.pickRandom(st)
}

func (s *Selector) pickLeastResponseTime(st *selectorState) Backend {
	var best Backend
	bestScore := float64(math.MaxFloat64)
	for _, b := range st.backends {
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

func (s *Selector) pickPowerOfTwoChoices(st *selectorState) Backend {
	n := len(st.backends)
	if n < 2 {
		return s.pickLeastConn(st)
	}

	rng := zulu.Rand()
	defer zulu.RandPut(rng)

	idx1 := rng.IntN(n)
	idx2 := rng.IntN(n - 1)
	if idx2 >= idx1 {
		idx2++
	}

	var candidates []int
	if st.backends[idx1].IsUsable() {
		candidates = append(candidates, idx1)
	}
	if st.backends[idx2].IsUsable() {
		candidates = append(candidates, idx2)
	}

	if len(candidates) == 0 {
		return s.pickLeastConn(st)
	}
	if len(candidates) == 1 {
		return st.backends[candidates[0]]
	}

	if st.backends[candidates[0]].InFlight() < st.backends[candidates[1]].InFlight() {
		return st.backends[candidates[0]]
	}
	return st.backends[candidates[1]]
}

func (s *Selector) pickConsistentHash(key uint64, st *selectorState) Backend {
	if st.ring == nil || len(st.ring.ring) == 0 {
		return s.pickRandom(st)
	}

	h := HashUint64(key)
	idx := st.ring.Get(h)
	if idx < 0 || idx >= len(st.backends) {
		return s.pickRandom(st)
	}

	for i := 0; i < len(st.backends); i++ {
		checkIdx := (idx + i) % len(st.backends)
		if st.backends[checkIdx].IsUsable() {
			return st.backends[checkIdx]
		}
	}
	return nil
}

func (s *Selector) Stop() {
	s.state.Store(nil)
}
