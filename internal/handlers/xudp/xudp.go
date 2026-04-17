package xudp

import (
	"sync"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/pkg/metrics"
)

// datagramBufPool recycles read buffers for the main listen loop.
var datagramBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, def.UDPBufSize)
		return &b
	},
}

func getDatagram() []byte {
	return *(datagramBufPool.Get().(*[]byte))
}

func putDatagram(b []byte) {
	datagramBufPool.Put(&b)
}

// Snapshot is the health/metrics snapshot for a single UDP backend.
// Mirrors xtcp.Snapshot so uptime rendering stays consistent.
type Snapshot struct {
	Address     string                  `json:"address"`
	Alive       bool                    `json:"alive"`
	ActiveSess  int64                   `json:"active_sessions"`
	Failures    int64                   `json:"failures"`
	MaxSessions int64                   `json:"max_sessions"`
	TotalReqs   uint64                  `json:"total_reqs"`
	Latency     metrics.LatencySnapshot `json:"latency_us"`
}
