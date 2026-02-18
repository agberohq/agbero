package zulu

import (
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"github.com/olekukonko/mappo"
)

// Route is a globally shared map that provides lifecycle-managed access to route configurations and their handlers.
var Route = mappo.NewCache(mappo.CacheOptions{
	MaximumSize: woos.CacheMax,
	OnDelete:    mappo.CloserDelete,
})

var TCP = mappo.NewCache(mappo.CacheOptions{
	MaximumSize: woos.CacheMax,
	OnDelete:    mappo.CloserDelete,
})

func GetCache[T any](it *mappo.Item) (T, bool) {
	var zero T
	if it == nil || it.Value == nil {
		return zero, false
	}
	v, ok := it.Value.(T)
	return v, ok
}
