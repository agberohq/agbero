package core

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

type RouteHandler struct {
	stripPrefixes []string
	strategy      string
	Backends      []*backendTarget
	rrCounter     uint64
}

type backendTarget struct {
	U        *url.URL
	proxy    *httputil.ReverseProxy
	Inflight atomic.Int64
}

func NewRouteHandler(route *woos.Route) *RouteHandler {
	h := &RouteHandler{
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
		rp.Transport = woos.SharedTransport

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

		h.Backends = append(h.Backends, &backendTarget{
			U:     target,
			proxy: rp,
		})
	}

	return h
}

func (h *RouteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(h.Backends) == 0 {
		http.Error(w, "No Backends configured", http.StatusBadGateway)
		return
	}

	b := h.PickBackend()
	if b == nil {
		http.Error(w, "No healthy Backends", http.StatusBadGateway)
		return
	}

	b.Inflight.Add(1)
	defer b.Inflight.Add(-1)

	b.proxy.ServeHTTP(w, r)
}

func (h *RouteHandler) PickBackend() *backendTarget {
	switch h.strategy {
	case woos.StrategyLeastConn, "least_conn":
		return h.pickLeastConn()
	case woos.StrategyRandom:
		return h.pickRandom()
	default: // "roundrobin"
		return h.pickRoundRobin()
	}
}

func (h *RouteHandler) pickRoundRobin() *backendTarget {
	n := uint64(len(h.Backends))
	i := atomic.AddUint64(&h.rrCounter, 1)
	return h.Backends[i%n]
}

func (h *RouteHandler) pickRandom() *backendTarget {
	n := len(h.Backends)
	if n == 1 {
		return h.Backends[0]
	}
	i := int(randUint64() % uint64(n))
	return h.Backends[i]
}

func (h *RouteHandler) pickLeastConn() *backendTarget {
	var (
		best *backendTarget
		min  int64
	)

	for i, b := range h.Backends {
		c := b.Inflight.Load()
		if i == 0 || c < min {
			min = c
			best = b
		}
	}
	return best
}
