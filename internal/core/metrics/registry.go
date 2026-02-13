package metrics

import "sync"

// DefaultRegistry is the singleton instance used to persist metrics
// across handler recreation cycles (e.g. by the Reaper).
var DefaultRegistry = NewRegistry()

type BackendStats struct {
	Activity *Activity
	Health   *Health
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
func (r *Registry) GetOrRegister(key string) *BackendStats {
	r.mu.Lock()
	defer r.mu.Unlock()

	if s, ok := r.items[key]; ok {
		return s
	}

	s := &BackendStats{
		Activity: NewActivityTracker(),
		Health:   NewHealthTracker(),
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

// Prune removes any keys not present in the keepKeys map.
func (r *Registry) Prune(keepKeys map[string]bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for k := range r.items {
		if !keepKeys[k] {
			delete(r.items, k)
		}
	}
}
