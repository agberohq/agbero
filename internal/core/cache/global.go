package cache

import "git.imaxinacion.net/aibox/agbero/internal/woos"

// Route is a globally shared map that provides lifecycle-managed access to route configurations and their handlers.
var Route = New(Options{
	MaximumSize: woos.CacheMax,
	OnDelete:    CloserDelete,
})
