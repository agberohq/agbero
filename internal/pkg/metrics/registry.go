package metrics

import (
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/olekukonko/mappo"
)

type BackendStats struct {
	Activity *Activity
}

func (s *BackendStats) Close() {
	if s.Activity != nil && s.Activity.Latency != nil {
		s.Activity.Latency.Close()
	}
}

type Registry struct {
	items *mappo.Concurrent[alaye.BackendKey, *BackendStats]
}

func NewRegistry() *Registry {
	return &Registry{
		items: mappo.NewConcurrent[alaye.BackendKey, *BackendStats](),
	}
}

func (r *Registry) GetOrRegister(key alaye.BackendKey) *BackendStats {
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

func (r *Registry) Get(key alaye.BackendKey) *BackendStats {
	stats, _ := r.items.Get(key)
	return stats
}

func (r *Registry) Prune(keepKeys map[alaye.BackendKey]bool) {
	var toClose []*BackendStats

	r.items.Range(func(k alaye.BackendKey, v *BackendStats) bool {
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

func (r *Registry) Close() {
	r.items.Range(func(k alaye.BackendKey, v *BackendStats) bool {
		v.Close()
		return true
	})
}

func (r *Registry) Clear() {
	r.items.Clear()
}
