package xhttp

import (
	"context"
	"net/http"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/balancer"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
)

// LoadBalancer wraps the new balancer package for HTTP backends
type LoadBalancer struct {
	selector    *balancer.Selector
	timeout     time.Duration
	stripPrefix []string
}

// httpBackend wraps xhttp.Backend to implement balancer.Backend interface
type httpBackend struct {
	*Backend
}

func (b httpBackend) Alive() bool     { return b.Backend.Alive.Load() }
func (b httpBackend) Weight() int     { return b.Backend.Weight }
func (b httpBackend) InFlight() int64 { return b.Backend.Activity.InFlight.Load() }

func (b httpBackend) ResponseTime() int64 {
	// Get average latency from metrics
	snap := b.Backend.Activity.Latency.Snapshot()
	if snap.Count == 0 {
		return 0
	}
	return snap.Avg // Changed from Mean to Avg
}

func NewLoadBalancer(backends []*Backend, strategy string, timeout time.Duration, stripPrefixes []string) *LoadBalancer {
	wrapped := make([]balancer.Backend, 0, len(backends))
	for _, b := range backends {
		if b != nil {
			wrapped = append(wrapped, httpBackend{b})
		}
	}

	lb := &LoadBalancer{
		timeout:     timeout,
		stripPrefix: append([]string(nil), stripPrefixes...),
	}
	lb.selector = balancer.NewSelector(wrapped, balancer.ParseStrategy(strategy))
	return lb
}

func (lb *LoadBalancer) Update(list []*Backend) {
	wrapped := make([]balancer.Backend, 0, len(list))
	for _, b := range list {
		if b != nil {
			wrapped = append(wrapped, httpBackend{b})
		}
	}
	lb.selector.Update(wrapped)
}

func (lb *LoadBalancer) Snapshot() []*Backend {
	// Return underlying backends
	var result []*Backend
	for _, hb := range lb.selector.Backends() {
		if b, ok := hb.(httpBackend); ok {
			result = append(result, b.Backend)
		}
	}
	return result
}

func (lb *LoadBalancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	be := lb.PickBackend(r)
	if be == nil {
		http.Error(w, "no healthy backends", http.StatusBadGateway)
		return
	}

	ctx := r.Context()
	if lb.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, lb.timeout)
		defer cancel()
	}

	be.ServeHTTP(w, r.WithContext(ctx))
}

func (lb *LoadBalancer) PickBackend(r *http.Request) *Backend {
	key := lb.hashKey(r)
	b := lb.selector.Pick(r, func() uint64 { return key })
	if b == nil {
		return nil
	}
	if hb, ok := b.(httpBackend); ok {
		return hb.Backend
	}
	return nil
}

func (lb *LoadBalancer) hashKey(r *http.Request) uint64 {
	switch lb.selector.Strategy {
	case balancer.StrategyIPHash:
		ip := clientip.ClientIP(r)
		return balancer.HashString(ip)
	case balancer.StrategyURLHash:
		path := r.URL.Path
		if path == "" {
			path = "/"
		}
		return balancer.HashString(path)
	default:
		return 0
	}
}
