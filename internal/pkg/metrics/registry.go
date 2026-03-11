package metrics

import (
	"github.com/olekukonko/mappo"
)

var DefaultRegistry = NewRegistry()

type BackendStats struct {
	Activity *Activity
}

func (s *BackendStats) Close() {
	if s.Activity != nil && s.Activity.Latency != nil {
		s.Activity.Latency.Close()
	}
}

type Registry struct {
	items *mappo.Concurrent[string, *BackendStats]
}

func NewRegistry() *Registry {
	return &Registry{
		items: mappo.NewConcurrent[string, *BackendStats](),
	}
}

func (r *Registry) GetOrRegister(key string) *BackendStats {
	stats := r.items.Compute(key, func(current *BackendStats, exists bool) (*BackendStats, bool) {
		if exists {
			return current, true
		}
		return &BackendStats{
			Activity: NewActivity(),
		}, true
	})
	return stats
}

func (r *Registry) Get(key string) *BackendStats {
	stats, _ := r.items.Get(key)
	return stats
}

func (r *Registry) Prune(keepKeys map[string]bool) {
	var toClose []*BackendStats

	r.items.Range(func(k string, v *BackendStats) bool {
		if !keepKeys[k] {
			toClose = append(toClose, v)
			r.items.Delete(k)
		}
		return true
	})

	for _, v := range toClose {
		v.Close()
	}
}
