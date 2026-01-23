// internal/core/routes.go
package core

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/olekukonko/ll"
)

type RouteHandler struct {
	stripPrefixes []string
	strategy      string
	Backends      []*Backend
	rrCounter     uint64
	timeout       time.Duration
}

// We need the logger here to pass to NewBackend
func NewRouteHandler(route *woos.Route, logger *ll.Logger) *RouteHandler {
	h := &RouteHandler{
		stripPrefixes: append([]string(nil), route.StripPrefixes...),
		strategy:      strings.ToLower(strings.TrimSpace(route.LBStrategy)),
	}

	if h.strategy == "" {
		h.strategy = "roundrobin"
	}

	// Parse Timeout
	if route.Timeouts != nil && route.Timeouts.Request != "" {
		if d, err := time.ParseDuration(route.Timeouts.Request); err == nil {
			h.timeout = d
		}
	}

	// Use the interface wrapper for the logger
	wrappedLogger := NewTLSLogger(logger)

	for _, raw := range route.Backends {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		b, err := NewBackend(raw, route, wrappedLogger)
		if err != nil {
			logger.Fields("backend", raw, "err", err).Error("failed to create backend")
			continue
		}
		h.Backends = append(h.Backends, b)
	}

	return h
}

func (h *RouteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(h.Backends) == 0 {
		http.Error(w, "No backends configured", http.StatusBadGateway)
		return
	}

	b := h.PickBackend()
	if b == nil {
		http.Error(w, "No healthy backends", http.StatusBadGateway)
		return
	}

	// Apply Route Timeout if configured
	if h.timeout > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
		defer cancel()
		r = r.WithContext(ctx)
		b.ServeHTTP(w, r)
	} else {
		b.ServeHTTP(w, r)
	}
}

func (h *RouteHandler) PickBackend() *Backend {
	// Optimization: If only 1 backend, skip LB logic (but check health)
	if len(h.Backends) == 1 {
		b := h.Backends[0]
		if b.Alive.Load() {
			return b
		}
		return nil
	}

	switch h.strategy {
	case woos.StrategyLeastConn, "least_conn":
		return h.pickLeastConn()
	case woos.StrategyRandom:
		return h.pickRandom()
	default: // "roundrobin"
		return h.pickRoundRobin()
	}
}

func (h *RouteHandler) pickRoundRobin() *Backend {
	n := uint64(len(h.Backends))
	// Try N times to find an alive backend
	for i := uint64(0); i < n; i++ {
		idx := atomic.AddUint64(&h.rrCounter, 1)
		b := h.Backends[idx%n]
		if b.Alive.Load() {
			return b
		}
	}
	return nil
}

func (h *RouteHandler) pickRandom() *Backend {
	n := len(h.Backends)
	// Try N times (statistical attempt)
	start := randUint64()
	for i := 0; i < n; i++ {
		idx := (start + uint64(i)) % uint64(n)
		b := h.Backends[idx]
		if b.Alive.Load() {
			return b
		}
	}
	return nil
}

func (h *RouteHandler) pickLeastConn() *Backend {
	var (
		best    *Backend
		minimal int64 = -1
	)

	for _, b := range h.Backends {
		if !b.Alive.Load() {
			continue
		}
		c := b.InFlight.Load()
		if minimal == -1 || c < minimal {
			minimal = c
			best = b
		}
	}
	return best
}

// Close gracefully stops background tasks (health checks)
func (h *RouteHandler) Close() {
	for _, b := range h.Backends {
		b.Stop()
	}
}
