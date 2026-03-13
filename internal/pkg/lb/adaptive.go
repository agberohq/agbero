package lb

import (
	"net/http"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/core/zulu"
)

type Adaptive struct {
	balancer        Balancer
	mu              sync.RWMutex
	performanceData map[Backend]*backendMetrics
	allBackends     []Backend
	learningRate    float64
	decayFactor     float64
	stopCh          chan struct{}
	stopOnce        sync.Once
}

type backendMetrics struct {
	successRate          float64
	avgLatency           float64
	lastUpdated          time.Time
	requestCount         uint64
	failureCount         uint64
	consecutiveSuccesses uint64
}

func NewAdaptive(child Balancer, learningRate float64) *Adaptive {
	if learningRate < 0 || learningRate > 1 {
		learningRate = 0.1
	}
	a := &Adaptive{
		balancer:        child,
		performanceData: make(map[Backend]*backendMetrics),
		learningRate:    learningRate,
		decayFactor:     0.95,
		stopCh:          make(chan struct{}),
	}
	go a.cleanupLoop()
	return a
}

func (s *Adaptive) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.Cleanup()
		case <-s.stopCh:
			return
		}
	}
}

func (s *Adaptive) Update(backends []Backend) {
	s.balancer.Update(backends)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.allBackends = make([]Backend, len(backends))
	copy(s.allBackends, backends)

	validBackends := make(map[Backend]struct{}, len(backends))
	for _, b := range backends {
		validBackends[b] = struct{}{}
	}

	for b := range s.performanceData {
		if _, exists := validBackends[b]; !exists {
			delete(s.performanceData, b)
		}
	}
}

func (s *Adaptive) Backends() []Backend {
	return s.balancer.Backends()
}

func (s *Adaptive) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	threshold := time.Now().Add(-1 * time.Hour)
	for b, m := range s.performanceData {
		if m.lastUpdated.Before(threshold) {
			delete(s.performanceData, b)
		}
	}
}

func (s *Adaptive) Pick(r *http.Request, keyFunc func() uint64) Backend {
	if randFloat() < s.learningRate {
		return s.balancer.Pick(r, keyFunc)
	}
	s.mu.RLock()
	if len(s.performanceData) < len(s.allBackends) {
		s.mu.RUnlock()
		return s.balancer.Pick(r, keyFunc)
	}
	var best Backend
	bestScore := -1.0
	for b, m := range s.performanceData {
		if !b.IsUsable() {
			continue
		}
		latencyScore := 1.0 / (1.0 + m.avgLatency/1000.0)
		inflightScore := 1.0 / (1.0 + float64(b.InFlight())/10.0)
		score := m.successRate*0.6 + latencyScore*0.25 + inflightScore*0.15
		if score > bestScore {
			bestScore = score
			best = b
		}
	}
	s.mu.RUnlock()
	if best != nil {
		return best
	}
	return s.balancer.Pick(r, keyFunc)
}

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

	alpha := 1.0 - s.decayFactor
	val := 1.0
	if failed {
		val = 0.0
	}
	m.successRate = m.successRate*(1.0-alpha) + val*alpha

	if latencyMicros > 0 {
		m.avgLatency = m.avgLatency*(1.0-alpha) + float64(latencyMicros)*alpha
	}
	m.lastUpdated = time.Now()
}

func (s *Adaptive) Stop() {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		if s.balancer != nil {
			s.balancer.Stop()
		}
	})
}

func randFloat() float64 {
	rng := zulu.Rand()
	defer zulu.RandPut(rng)
	return rng.Float64()
}
