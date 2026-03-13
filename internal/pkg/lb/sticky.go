package lb

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/mappo"
)

// Sticky adds session persistence using jack.Reaper for efficient TTL management
type Sticky struct {
	balancer  Balancer
	reaper    *jack.Reaper
	cache     *mappo.LRU[string, Backend]
	extractor func(*http.Request) string
	ttl       time.Duration
	mu        sync.RWMutex
	stopOnce  sync.Once
}

// NewSticky wraps a balancer with session affinity.
// Uses jack.Reaper for O(log N) expiration and mappo.LRU for bounded caching.
func NewSticky(child Balancer, ttl time.Duration, extractor func(*http.Request) string) *Sticky {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}

	if extractor == nil {
		extractor = zulu.IP.ClientIP
	}

	s := &Sticky{
		balancer:  child,
		ttl:       ttl,
		extractor: extractor,
		cache:     mappo.NewLRU[string, Backend](1024),
	}

	s.reaper = jack.NewReaper(ttl, jack.ReaperWithHandler(func(ctx context.Context, id string) {
		s.cache.Delete(id)
	}))
	s.reaper.Start()

	return s
}

// Update propagates update and clears invalid sticky sessions.
func (s *Sticky) Update(backends []Backend) {
	s.balancer.Update(backends)

	valid := make(map[Backend]struct{}, len(backends))
	for _, b := range backends {
		valid[b] = struct{}{}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var toDelete []string
	s.cache.Range(func(key string, value Backend) bool {
		if _, ok := valid[value]; !ok {
			toDelete = append(toDelete, key)
		}
		return true
	})

	for _, key := range toDelete {
		s.cache.Delete(key)
		s.reaper.Remove(key)
	}
}

func (s *Sticky) Backends() []Backend {
	return s.balancer.Backends()
}

// Stop gracefully shuts down the reaper and child balancer.
func (s *Sticky) Stop() {
	s.stopOnce.Do(func() {
		s.reaper.Stop()
		if s.balancer != nil {
			s.balancer.Stop()
		}
	})
}

// Pick selects a backend with session affinity.
func (s *Sticky) Pick(r *http.Request, keyFunc func() uint64) Backend {
	sessionID := s.extractor(r)
	if sessionID == "" {
		return s.balancer.Pick(r, keyFunc)
	}

	s.mu.RLock()
	if backend, ok := s.cache.Get(sessionID); ok && backend.IsUsable() {
		s.mu.RUnlock()
		s.reaper.Touch(sessionID)
		return backend
	}
	s.mu.RUnlock()

	backend := s.balancer.Pick(r, keyFunc)
	if backend != nil {
		s.mu.Lock()
		s.cache.Set(sessionID, backend)
		s.mu.Unlock()
		s.reaper.Touch(sessionID)
	}

	return backend
}

// GetStats returns statistics about the sticky table.
func (s *Sticky) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"cached_entries": s.cache.Len(),
		"reaper_tasks":   s.reaper.Count(),
	}
}
