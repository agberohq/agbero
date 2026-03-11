package health

import (
	"github.com/olekukonko/mappo"
)

// Registry provides a high-performance, lock-free global store for backend health scores.
type Registry struct {
	scores *mappo.Concurrent[string, *Score]
}

// NewRegistry initializes an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		scores: mappo.NewConcurrent[string, *Score](),
	}
}

// Set stores a health score at the given key, overwriting any existing value.
func (r *Registry) Set(key string, score *Score) {
	r.scores.Set(key, score)
}

// Get retrieves a health score by its key.
func (r *Registry) Get(key string) (*Score, bool) {
	return r.scores.Get(key)
}

// GetOrSet retrieves an existing score or atomically sets a new one if it doesn't exist.
func (r *Registry) GetOrSet(key string, score *Score) *Score {
	s := r.scores.Compute(key, func(current *Score, exists bool) (newValue *Score, keep bool) {
		if exists {
			return current, true
		}
		return score, true
	})
	return s
}

// Delete removes a score from the registry.
func (r *Registry) Delete(key string) {
	r.scores.Delete(key)
}

// Clear empties the entire registry.
func (r *Registry) Clear() {
	r.scores.Clear()
}

// GlobalRegistry is the default global health registry instance.
var GlobalRegistry = NewRegistry()
