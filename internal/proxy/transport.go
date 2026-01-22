package proxy

import (
	"net"
	"net/http"
	"time"
)

// SharedTransport is a globally tuned transport for upstream connections.
// In a real app, you might want distinct transports per backend if requirements differ drastically,
// but a shared tuned transport is better than the default.
var SharedTransport = &http.Transport{
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
