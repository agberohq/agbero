package zulu

import (
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	cache2 "git.imaxinacion.net/aibox/agbero/internal/pkg/cache"
)

// Route is a globally shared map that provides lifecycle-managed access to route configurations and their handlers.
var Route = cache2.New(cache2.Options{
	MaximumSize: woos.CacheMax,
	OnDelete:    cache2.CloserDelete,
})

var TCP = cache2.New(cache2.Options{
	MaximumSize: woos.CacheMax,
	OnDelete:    cache2.CloserDelete,
})
