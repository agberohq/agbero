package zulu

import (
	mrand "math/rand/v2"
	"sync"

	"github.com/agberohq/agbero/internal/core/woos"
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

var rngPool = sync.Pool{
	New: func() any {
		// Use PCG with seeds from the global random source
		return mrand.New(mrand.NewPCG(
			mrand.Uint64(),
			mrand.Uint64(),
		))
	},
}

func Rand() *mrand.Rand {
	r := rngPool.Get().(*mrand.Rand)
	return r
}

func RandPut(r *mrand.Rand) {
	rngPool.Put(r)
}
