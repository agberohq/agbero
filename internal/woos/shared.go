package woos

import (
	"net"
	"net/http"
)

var Transport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   DefaultTransportDialTimeout,
		KeepAlive: DefaultTransportKeepAlive,
	}).DialContext,

	ForceAttemptHTTP2: true,

	MaxIdleConns:        DefaultTransportMaxIdleConns,
	MaxIdleConnsPerHost: DefaultTransportMaxIdleConnsPerHost,
	IdleConnTimeout:     DefaultTransportIdleConnTimeout,

	TLSHandshakeTimeout:   DefaultTransportTLSHandshakeTimeout,
	ResponseHeaderTimeout: DefaultTransportResponseHeaderTimeout,
	ExpectContinueTimeout: 0, // Explicitly disabled as per previous fixes
}
