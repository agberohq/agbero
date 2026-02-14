package lb

import (
	"net/http"
	"sync"
	"time"
)

// Sticky adds session persistence.
type Sticky struct {
	balancer    Balancer
	stickyTable sync.Map // map[string]stickyEntry
	ttl         time.Duration
	extractor   func(*http.Request) string
}

type stickyEntry struct {
	backend Backend
	expires time.Time
}

// NewSticky wraps a balancer with session affinity.
func NewSticky(child Balancer, ttl time.Duration, extractor func(*http.Request) string) *Sticky {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &Sticky{
		balancer:  child,
		ttl:       ttl,
		extractor: extractor,
	}
}

// Update propagates update and clears invalid sticky sessions.
func (s *Sticky) Update(backends []Backend) {
	s.balancer.Update(backends)

	// Create a quick lookup for valid backends
	valid := make(map[Backend]bool)
	for _, b := range backends {
		valid[b] = true
	}

	// Prune sticky entries pointing to dead/removed backends
	s.stickyTable.Range(func(key, value any) bool {
		entry := value.(stickyEntry)
		if !valid[entry.backend] {
			s.stickyTable.Delete(key)
		}
		return true
	})
}

// Cleanup removes expired entries from the map.
func (s *Sticky) Cleanup() {
	now := time.Now()
	s.stickyTable.Range(func(key, value any) bool {
		entry := value.(stickyEntry)
		if now.After(entry.expires) {
			s.stickyTable.Delete(key)
		}
		return true
	})
}

func (s *Sticky) Pick(r *http.Request, keyFunc func() uint64) Backend {
	// 1. Extract Session ID (Cookie/Header/IP)
	sessionID := ""
	if s.extractor != nil {
		sessionID = s.extractor(r)
	}

	// 2. Check Table
	if sessionID != "" {
		if val, ok := s.stickyTable.Load(sessionID); ok {
			entry := val.(stickyEntry)
			// Check expiration and liveness
			if time.Now().Before(entry.expires) && entry.backend.Alive() {
				return entry.backend
			}
			s.stickyTable.Delete(sessionID)
		}
	}

	// 3. Fallback to child balancer
	backend := s.balancer.Pick(r, keyFunc)

	// 4. Store new affinity
	if backend != nil && sessionID != "" {
		s.stickyTable.Store(sessionID, stickyEntry{
			backend: backend,
			expires: time.Now().Add(s.ttl),
		})
	}

	return backend
}
