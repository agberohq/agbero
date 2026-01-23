package woos

import (
	"sync"
	"time"
)

const (
	Name        = "agbero"
	Version     = "0.0.2"
	Description = "Production reverse proxy with Let's Encrypt support"
)

const (
	StrategyRandom    = "random"
	StrategyLeastConn = "leastconn"
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
)

// RouteCache stores compiled handlers per unique route definition.
// Keyed by a stable string derived from route settings (path/strategy/Backends/etc).
var RouteCache sync.Map // map[string]*RouteHandler
