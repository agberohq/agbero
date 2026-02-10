package cache

// Route is a globally shared map that provides lifecycle-managed access to route configurations and their handlers.
var Route = NewMap()
