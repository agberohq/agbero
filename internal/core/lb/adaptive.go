package lb

import (
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
)

// Adaptive learns from past performance
type Adaptive struct {
	*Selector
	mu              sync.RWMutex
	performanceData map[Backend]*backendMetrics
	learningRate    float64 // 0.0-1.0, higher = more exploration
	decayFactor     float64
}

type backendMetrics struct {
	successRate          float64
	avgLatency           float64
	lastUpdated          time.Time
	requestCount         uint64
	failureCount         uint64
	consecutiveSuccesses uint64
}

// NewAdaptive creates a learning-based selector
func NewAdaptive(selector *Selector, learningRate float64) *Adaptive {
	if learningRate < 0 || learningRate > 1 {
		learningRate = 0.1
	}
	return &Adaptive{
		Selector:        selector,
		performanceData: make(map[Backend]*backendMetrics),
		learningRate:    learningRate,
		decayFactor:     0.95,
	}
}

// RecordResult updates metrics after a request
func (s *Adaptive) RecordResult(backend Backend, latencyMicros int64, failed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, exists := s.performanceData[backend]
	if !exists {
		m = &backendMetrics{}
		s.performanceData[backend] = m
	}

	m.requestCount++
	if failed {
		m.failureCount++
		m.consecutiveSuccesses = 0
	} else {
		m.consecutiveSuccesses++
	}

	// Exponential moving average for success rate
	alpha := 1.0 - s.decayFactor
	if failed {
		m.successRate = m.successRate*(1.0-alpha) + 0.0*alpha
	} else {
		m.successRate = m.successRate*(1.0-alpha) + 1.0*alpha
	}

	// Exponential moving average for latency
	if latencyMicros > 0 {
		m.avgLatency = m.avgLatency*(1.0-alpha) + float64(latencyMicros)*alpha
	}

	m.lastUpdated = time.Now()
}

// PickAdaptive selects based on learned performance
func (s *Adaptive) PickAdaptive(r *http.Request, keyFunc func() uint64) Backend {
	// Exploration: random selection
	if randFloat() < s.learningRate {
		return s.pickRandom()
	}

	// Exploitation: best performing backend
	s.mu.RLock()
	defer s.mu.RUnlock()

	var best Backend
	bestScore := -1.0

	for _, b := range s.backends {
		if !b.Alive() {
			continue
		}

		m, exists := s.performanceData[b]
		if !exists {
			// New backend, give it a chance with bonus
			return b
		}

		// Score: high success rate, low latency, low inflight
		latencyScore := 1.0 / (1.0 + m.avgLatency/1000.0) // Normalize to ~0-1
		inflightScore := 1.0 / (1.0 + float64(b.InFlight())/10.0)

		// Penalize backends with low success rate heavily
		successWeight := 0.6
		latencyWeight := 0.25
		inflightWeight := 0.15

		score := m.successRate*successWeight + latencyScore*latencyWeight + inflightScore*inflightWeight

		// Boost new backends (fewer than 10 requests)
		if m.requestCount < 10 {
			score += 0.1
		}

		if score > bestScore {
			bestScore = score
			best = b
		}
	}

	if best == nil {
		return s.Selector.Pick(r, keyFunc)
	}
	return best
}

// PickAdaptiveWithHash uses xxhash for key-based selection with fallback
func (s *Adaptive) PickAdaptiveWithHash(r *http.Request, key string) Backend {
	// Use xxhash for consistent hashing of the key
	h := xxhash.Sum64String(key)

	// Exploration based on hash for deterministic testing
	if float64(h%1000)/1000.0 < s.learningRate {
		return s.pickRandom()
	}

	return s.PickAdaptive(r, func() uint64 { return h })
}

func randFloat() float64 {
	rng := rngPool.Get().(*rand.Rand)
	defer rngPool.Put(rng)
	return rng.Float64()
}
