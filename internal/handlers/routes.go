package handlers

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/backend"
	"git.imaxinacion.net/aibox/agbero/internal/core/tlss"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/auth"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/compress"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/headers"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
)

type RouteHandler struct {
	// The final handler in the chain (Load Balancer)
	// wrapped by middlewares.
	handler http.Handler

	// Internal access needed for "Close" and Metrics
	Backends []*backend.Backend
}

func NewRouteHandler(route *alaye.Route, logger *ll.Logger) *RouteHandler {
	if route == nil {
		logger.Error("nil route")
		return nil
	}

	// Validate route semantics first (web XOR backends, required fields, etc.)
	if err := route.Validate(); err != nil {
		logger.Fields("path", route.Path, "err", err).Error("invalid route config")
		return nil
	}

	logger.Fields("path", route.Path, "web_root_raw", string(route.Web.Root), "backends", route.Backends).
		Debug("creating route handler")

	// At this point route.Validate() guaranteed exactly one of these:
	// - web route with root set
	// - proxy route with backends set
	if route.Web.Root.IsSet() {
		logger.Debug("treating as WEB route")
		return newWebRouteHandler(route, logger)
	}

	logger.Debug("treating as PROXY route")
	return newProxyRouteHandler(route, logger)
}

func newWebRouteHandler(route *alaye.Route, logger *ll.Logger) *RouteHandler {
	// Web route doesn't need backends or load balancing
	chain := &webHandler{
		route:  route,
		logger: logger,
	}

	// Build middleware chain (same as proxy routes)
	var handler http.Handler = chain

	// Authentication
	if route.BasicAuth != nil && len(route.BasicAuth.Users) > 0 {
		handler = auth.Basic(route.BasicAuth)(handler)
	}
	if route.ForwardAuth != nil && route.ForwardAuth.URL != "" {
		handler = auth.Forward(route.ForwardAuth)(handler)
	}

	// Headers
	if route.Headers != nil {
		handler = headers.Headers(route.Headers)(handler)
	}

	// Compression
	if route.CompressionConfig.Compression {
		handler = compress.Compress(route)(handler)
	}

	return &RouteHandler{
		handler:  handler,
		Backends: nil, // No backends for web routes
	}
}

func newProxyRouteHandler(route *alaye.Route, logger *ll.Logger) *RouteHandler {
	// 1. Initialize Load Balancer Logic
	lb := &LoadBalancerHandler{
		stripPrefixes: append([]string(nil), route.StripPrefixes...),
		strategy:      strings.ToLower(strings.TrimSpace(route.LBStrategy)),
	}

	if lb.strategy == "" {
		lb.strategy = alaye.StrategyRoundRobin // Ensure this constant exists in woos, or use "roundrobin"
	}

	if route.Timeouts != nil && route.Timeouts.Request != 0 {
		lb.timeout = route.Timeouts.Request
	}

	// 2. Initialize Backends
	// We need to wrap the logger to match the backend constructor interface
	wrappedLogger := tlss.NewTLSLogger(logger)

	for _, raw := range route.Backends {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		b, err := backend.NewBackend(raw, route, wrappedLogger)
		if err != nil {
			logger.Fields("backend", raw, "err", err).Error("failed to create backend")
			continue
		}
		lb.Backends = append(lb.Backends, b)
	}

	// 3. Build Middleware Chain
	// The chain is built "outside-in". The last one applied wraps everything else.
	// Execution Order: Compress -> Headers -> Auth -> LoadBalancer

	var chain http.Handler = lb

	// Layer 3: Authentication (Inner)
	// Protect the resource access
	if route.BasicAuth != nil && len(route.BasicAuth.Users) > 0 {
		chain = auth.Basic(route.BasicAuth)(chain)
	}
	if route.ForwardAuth != nil && route.ForwardAuth.URL != "" {
		chain = auth.Forward(route.ForwardAuth)(chain)
	}

	// Layer 2: Headers (Middle)
	// Modify headers before Auth sees them (Request) or before Compress sees them (Response)
	if route.Headers != nil {
		chain = headers.Headers(route.Headers)(chain)
	}

	// Layer 1: Compression (Outer)
	// Compresses the final byte stream.
	if route.CompressionConfig.Compression {
		chain = compress.Compress(route)(chain)
	}

	return &RouteHandler{
		handler:  chain,
		Backends: lb.Backends,
	}
}

func (h *RouteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.handler.ServeHTTP(w, r)
}

func (h *RouteHandler) Close() {
	for _, b := range h.Backends {
		b.Stop()
	}
}

// --- Internal Load Balancer Logic ---

type LoadBalancerHandler struct {
	stripPrefixes []string
	strategy      string
	Backends      []*backend.Backend
	rrCounter     uint64
	timeout       time.Duration
}

func (lb *LoadBalancerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(lb.Backends) == 0 {
		http.Error(w, "No backends configured", http.StatusBadGateway)
		return
	}

	b := lb.PickBackend()
	if b == nil {
		http.Error(w, "No healthy backends", http.StatusBadGateway)
		return
	}

	// Apply Route Timeout
	if lb.timeout > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), lb.timeout)
		defer cancel()
		r = r.WithContext(ctx)
		b.ServeHTTP(w, r)
	} else {
		b.ServeHTTP(w, r)
	}
}

func (lb *LoadBalancerHandler) PickBackend() *backend.Backend {
	if len(lb.Backends) == 1 {
		b := lb.Backends[0]
		if b.Alive.Load() {
			return b
		}
		return nil
	}

	switch lb.strategy {
	case alaye.StrategyLeastConn:
		return lb.pickLeastConn()
	case alaye.StrategyRandom:
		return lb.pickRandom()
	default:
		return lb.pickRoundRobin()
	}
}

func (lb *LoadBalancerHandler) pickRoundRobin() *backend.Backend {
	n := uint64(len(lb.Backends))
	for i := uint64(0); i < n; i++ {
		idx := atomic.AddUint64(&lb.rrCounter, 1)
		b := lb.Backends[idx%n]
		if b.Alive.Load() {
			return b
		}
	}
	return nil
}

func (lb *LoadBalancerHandler) pickRandom() *backend.Backend {
	n := len(lb.Backends)
	start := randUint64()
	for i := 0; i < n; i++ {
		idx := (start + uint64(i)) % uint64(n)
		b := lb.Backends[idx]
		if b.Alive.Load() {
			return b
		}
	}
	return nil
}

func (lb *LoadBalancerHandler) pickLeastConn() *backend.Backend {
	var (
		best *backend.Backend
		min  int64 = -1
	)

	// To avoid stampeding the first backend when all have 0 conns,
	// start iteration at a random offset
	n := len(lb.Backends)
	start := int(randUint64() % uint64(n))

	for i := 0; i < n; i++ {
		idx := (start + i) % n
		b := lb.Backends[idx]

		if !b.Alive.Load() {
			continue
		}
		c := b.InFlight.Load()
		if min == -1 || c < min {
			min = c
			best = b
		}
	}
	return best
}

var fallbackRand uint64

func randUint64() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err == nil {
		return binary.LittleEndian.Uint64(b[:])
	}
	return atomic.AddUint64(&fallbackRand, 1)
}
