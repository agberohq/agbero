package alaye

import (
	"time"
)

const (
	ModeLocalAuto = "auto" // Auto-generate local certificates
)

const (
	StrategyRandom            = "random"
	StrategyLeastConn         = "least_conn"
	StrategyRoundRobin        = "round_robin"
	StrategyIPHash            = "ip_hash"
	StrategyURLHash           = "url_hash"
	StrategyWeightedLeastConn = "weighted_least_conn"
)

// Default Timeouts
const (
	DefaultReadTimeout       = 10 * time.Second
	DefaultWriteTimeout      = 30 * time.Second
	DefaultIdleTimeout       = 120 * time.Second
	DefaultReadHeaderTimeout = 5 * time.Second
)

// Default Limits
const (
	DefaultMaxHeaderBytes = 1 << 20 // 1MB
	DefaultMaxBodySize    = 2 << 20 // 2MB
)

type TlsMode string

const (
	ModeLocalNone   TlsMode = "none"
	ModeLocalCert   TlsMode = "local"
	ModeLetsEncrypt TlsMode = "letsencrypt"
	ModeCustomCA    TlsMode = "custom_ca"
)
