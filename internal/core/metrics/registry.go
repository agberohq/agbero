package metrics

import (
	"sync"
	"sync/atomic"
)

var DefaultRegistry = NewRegistry()

type BackendStats struct {
	Activity *Activity
	Health   *Health
	Alive    *atomic.Bool
}

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

func (r *Registry) Get(key string) *BackendStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.items[key]
}

func (r *Registry) Prune(keepKeys map[string]bool) {
	var toClose []*BackendStats

	r.mu.Lock()
	for k, v := range r.items {
		if !keepKeys[k] {
			toClose = append(toClose, v)
			delete(r.items, k)
		}
	}
	r.mu.Unlock()

	for _, v := range toClose {
		v.Close()
	}
}
