package woos

import (
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// RouteCacheItem wraps the handler with usage tracking for the Reaper
type RouteCacheItem struct {
	Handler      any          // *core.RouteHandler
	LastAccessed atomic.Int64 // UnixNano
}

// RouteCache stores compiled handlers per unique route definition.
// Keyed by a stable string derived from route settings (path/strategy/Backends/etc).
// Value is *RouteCacheItem
var RouteCache sync.Map

var Transport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          1000,
	MaxIdleConnsPerHost:   100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}
