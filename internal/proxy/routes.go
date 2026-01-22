package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"git.imaxinacion.net/aibox/agbero/internal/config"
)

// routeCache stores compiled handlers per unique route definition.
// Keyed by a stable string derived from route settings (path/strategy/backends/etc).
var routeCache sync.Map // map[string]*routeHandler

type routeHandler struct {
	stripPrefixes []string
	strategy      string
	backends      []*backendTarget
	rrCounter     uint64
}

type backendTarget struct {
	u        *url.URL
	proxy    *httputil.ReverseProxy
	inflight atomic.Int64
}

func newRouteHandler(route *config.Route) *routeHandler {
	h := &routeHandler{
		stripPrefixes: append([]string(nil), route.StripPrefixes...),
		strategy:      strings.ToLower(strings.TrimSpace(route.LBStrategy)),
	}

	if h.strategy == "" {
		h.strategy = "roundrobin"
	}

	for _, raw := range route.Backends {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}

		target := u // Pointer copy

		rp := httputil.NewSingleHostReverseProxy(target)

		// PERFORMANCE: Use shared transport
		rp.Transport = config.SharedTransport

		// Hardening: Explicit FlushInterval (prevents buffering issues)
		rp.FlushInterval = -1

		origDirector := rp.Director
		rp.Director = func(req *http.Request) {
			origDirector(req)
			req.Host = target.Host
			// Remove hop-by-hop headers
			req.Header.Del("Connection")
			req.Header.Del("Keep-Alive")
			req.Header.Del("Proxy-Authenticate")
			req.Header.Del("Proxy-Authorization")
			req.Header.Del("Te")
			req.Header.Del("Trailers")
			req.Header.Del("Transfer-Encoding")
			req.Header.Del("Upgrade")
		}

		h.backends = append(h.backends, &backendTarget{
			u:     target,
			proxy: rp,
		})
	}

	return h
}

func (h *routeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(h.backends) == 0 {
		http.Error(w, "No backends configured", http.StatusBadGateway)
		return
	}

	b := h.pickBackend()
	if b == nil {
		http.Error(w, "No healthy backends", http.StatusBadGateway)
		return
	}

	b.inflight.Add(1)
	defer b.inflight.Add(-1)

	b.proxy.ServeHTTP(w, r)
}

func (h *routeHandler) pickBackend() *backendTarget {
	switch h.strategy {
	case config.StrategyLeastConn, "least_conn":
		return h.pickLeastConn()
	case config.StrategyRandom:
		return h.pickRandom()
	default: // "roundrobin"
		return h.pickRoundRobin()
	}
}

func (h *routeHandler) pickRoundRobin() *backendTarget {
	n := uint64(len(h.backends))
	i := atomic.AddUint64(&h.rrCounter, 1)
	return h.backends[i%n]
}

func (h *routeHandler) pickRandom() *backendTarget {
	n := len(h.backends)
	if n == 1 {
		return h.backends[0]
	}
	i := int(randUint64() % uint64(n))
	return h.backends[i]
}

func (h *routeHandler) pickLeastConn() *backendTarget {
	var (
		best *backendTarget
		min  int64
	)

	for i, b := range h.backends {
		c := b.inflight.Load()
		if i == 0 || c < min {
			min = c
			best = b
		}
	}
	return best
}
