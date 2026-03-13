package zulu

import (
	"io"
	mrand "math/rand/v2"
	"sync"

	"github.com/olekukonko/mappo"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
)

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

func Table(output io.Writer) *tablewriter.Table {
	table := tablewriter.NewTable(
		output,
		tablewriter.WithRendition(tw.Rendition{
			Settings: tw.Settings{
				Separators: tw.Separators{BetweenColumns: tw.Off},
			},
		}),
		tablewriter.WithSymbols(tw.NewSymbols(tw.StyleRounded)),
	)

	return table
}
