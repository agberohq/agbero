package woos

import (
	"net"
	"net/http"
	"sync"
	"sync/atomic"
)

// RouteCacheItem wraps the handler with usage tracking for the Reaper
type RouteCacheItem struct {
	Handler      any          `json:"handler"`       // *core.RouteHandler
	LastAccessed atomic.Int64 `json:"last_accessed"` // UnixNano
}

// RouteCache stores compiled handlers per unique route definition.
// Keyed by a stable string derived from route settings (path/strategy/Backends/etc).
// Value is *RouteCacheItem
var RouteCache sync.Map

var Transport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   DefaultTransportDialTimeout, // was 30s
		KeepAlive: DefaultTransportKeepAlive,
	}).DialContext,

	ForceAttemptHTTP2: true,

	MaxIdleConns:        DefaultTransportMaxIdleConns,
	MaxIdleConnsPerHost: DefaultTransportMaxIdleConnsPerHost,
	IdleConnTimeout:     DefaultTransportIdleConnTimeout,

	TLSHandshakeTimeout:   DefaultTransportTLSHandshakeTimeout,   //
	ResponseHeaderTimeout: DefaultTransportResponseHeaderTimeout, //
	ExpectContinueTimeout: DefaultTransportExpectContinueTimeout,
}
