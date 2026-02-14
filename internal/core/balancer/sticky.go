package balancer

import (
	"net/http"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
)

// StickySelector adds session persistence on top of base Selector
type StickySelector struct {
	*Selector
	stickyTable sync.Map // map[string]stickyEntry
	ttl         time.Duration
}

type stickyEntry struct {
	backendIdx int
	expires    time.Time
}

// NewStickySelector wraps a selector with session affinity
func NewStickySelector(selector *Selector, ttl time.Duration) *StickySelector {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &StickySelector{
		Selector: selector,
		ttl:      ttl,
	}
}

// PickWithSticky selects backend with session affinity
func (s *StickySelector) PickWithSticky(r *http.Request, keyFunc func() uint64, sessionExtractor func(*http.Request) string) Backend {
	sessionID := sessionExtractor(r)
	if sessionID == "" {
		return s.Selector.Pick(r, keyFunc)
	}

	// Check sticky table
	if entry, ok := s.stickyTable.Load(sessionID); ok {
		e := entry.(stickyEntry)
		if time.Now().Before(e.expires) {
			s.mu.RLock()
			if e.backendIdx < len(s.backends) && s.backends[e.backendIdx].Alive() {
				s.mu.RUnlock()
				return s.backends[e.backendIdx]
			}
			s.mu.RUnlock()
		}
		s.stickyTable.Delete(sessionID)
	}

	// Pick new backend
	backend := s.Selector.Pick(r, keyFunc)
	if backend != nil {
		idx := s.findBackendIndex(backend)
		if idx >= 0 {
			s.stickyTable.Store(sessionID, stickyEntry{
				backendIdx: idx,
				expires:    time.Now().Add(s.ttl),
			})
		}
	}

	return backend
}

// PickWithStickyHash uses xxhash for session key hashing
func (s *StickySelector) PickWithStickyHash(r *http.Request, sessionKey string) Backend {
	// Hash the session key for better distribution if used for backend selection
	hasher := xxhash.New()
	hasher.WriteString(sessionKey)
	hashedKey := hasher.Sum64()

	return s.PickWithSticky(r, func() uint64 { return hashedKey }, func(*http.Request) string {
		return sessionKey
	})
}

func (s *StickySelector) findBackendIndex(target Backend) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i, b := range s.backends {
		if b == target {
			return i
		}
	}
	return -1
}

// Cleanup removes expired entries (call periodically)
func (s *StickySelector) Cleanup() {
	now := time.Now()
	s.stickyTable.Range(func(key, value any) bool {
		if entry := value.(stickyEntry); now.After(entry.expires) {
			s.stickyTable.Delete(key)
		}
		return true
	})
}
