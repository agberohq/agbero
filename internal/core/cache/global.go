package cache

import (
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
)

// Route is a globally shared map that provides lifecycle-managed access to route configurations and their handlers.
var Route = New(Options{
	MaximumSize: woos.CacheMax,
	OnDelete:    CloserDelete,
})

var TCP = New(Options{
	MaximumSize: woos.CacheMax,
	OnDelete:    CloserDelete,
})
