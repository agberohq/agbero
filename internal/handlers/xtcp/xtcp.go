package xtcp

import (
	"fmt"
	"sync"

	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/pkg/metrics"
)

var proxyBufPool = zulu.NewBufferPool()

var checkBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 1024)
		return &b
	},
}

func getCheckBuf() []byte {
	return *(checkBufPool.Get().(*[]byte))
}

func putCheckBuf(b []byte) {
	checkBufPool.Put(&b)
}

func parsePort(s string) uint16 {
	var p uint16
	fmt.Sscanf(s, "%d", &p)
	return p
}

type Snapshot struct {
	Address     string
	Alive       bool
	ActiveConns int64
	Failures    int64
	MaxConns    int64
	TotalReqs   uint64
	Latency     metrics.LatencySnapshot
}
