package xudp

import (
	"sync"

	"github.com/agberohq/agbero/internal/pkg/metrics"
)

const (
	// udpBufSize is the maximum UDP datagram size we allocate for.
	// 65535 is the theoretical max; 9000 covers jumbo frames.
	udpBufSize = 65535

	// defaultSessionTTL is how long a client→backend mapping is kept
	// alive after the last datagram. ICE keepalives fire every ~15s so
	// 30s is a safe default for WebRTC. DNS callers get shorter TTLs.
	defaultSessionTTLSeconds = 30

	// defaultMaxSessions caps the session table. Prevents OOM from
	// port-scan floods. Each session is ~200 bytes so 100k ≈ 20 MB.
	defaultMaxSessions = 100_000

	// sweepInterval is how often the session sweeper runs.
	sweepIntervalSeconds = 10

	// dialTimeout for connecting to a UDP backend.
	dialTimeoutSeconds = 5

	// healthProbeTimeout is the default timeout for a UDP health probe.
	healthProbeTimeoutSeconds = 2

	// healthProbeInterval is the default health probe interval.
	healthProbeIntervalSeconds = 5

	// backendRetry is how many backends to try before giving up.
	backendRetry = 3

	sweepRoutineName = "xudp-session-sweeper"
	sweepPoolSize    = 1
)

// datagramBufPool recycles read buffers for the main listen loop.
var datagramBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, udpBufSize)
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
