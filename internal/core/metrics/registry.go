package metrics

import (
	"sync"
	"sync/atomic"
)

// DefaultRegistry is the singleton instance used to persist metrics
// across handler recreation cycles (e.g. by the Reaper).
var DefaultRegistry = NewRegistry()

type BackendStats struct {
	Activity *Activity
	Health   *Health
	Alive    *atomic.Bool
}

// Close releases resources associated with the stats (e.g. Latency goroutines).
func (s *BackendStats) Close() {
	if s.Activity != nil && s.Activity.Latency != nil {
		s.Activity.Latency.Close()
	}
}

type Registry struct {
	mu    sync.RWMutex
	items map[string]*BackendStats
}

func NewRegistry() *Registry {
	return &Registry{
		items: make(map[string]*BackendStats),
	}
}

// GetOrRegister returns existing stats for the key or creates new ones.
// It initializes Alive to true for new entries.
func (r *Registry) GetOrRegister(key string) *BackendStats {
	r.mu.Lock()
	defer r.mu.Unlock()

	if s, ok := r.items[key]; ok {
		return s
	}

	alive := &atomic.Bool{}
	alive.Store(true)

	s := &BackendStats{
		Activity: NewActivityTracker(),
		Health:   NewHealthTracker(),
		Alive:    alive,
	}
	r.items[key] = s
	return s
}

// Get returns existing stats or nil.
func (r *Registry) Get(key string) *BackendStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.items[key]
}

// Prune removes any keys not present in the keepKeys map and closes them.
func (r *Registry) Prune(keepKeys map[string]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for k, v := range r.items {
		if !keepKeys[k] {
			v.Close() // Stop background goroutines (e.g. Latency histogram)
			delete(r.items, k)
		}
	}
}
