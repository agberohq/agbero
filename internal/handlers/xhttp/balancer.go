package xhttp

import (
	"context"
	"net/http"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/lb"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
)

// Balancer wraps the new balancer package for HTTP backends
type Balancer struct {
	selector    *lb.Selector
	timeout     time.Duration
	stripPrefix []string
}

func NewLoadBalancer(backends []*Backend, strategy string, timeout time.Duration, stripPrefixes []string) *Balancer {
	wrapped := make([]lb.Backend, 0, len(backends))
	for _, b := range backends {
		if b != nil {
			wrapped = append(wrapped, httpBackend{b})
		}
	}

	load := &Balancer{
		timeout:     timeout,
		stripPrefix: append([]string(nil), stripPrefixes...),
	}
	load.selector = lb.NewSelector(wrapped, lb.ParseStrategy(strategy))
	return load
}

func (b *Balancer) Update(list []*Backend) {
	wrapped := make([]lb.Backend, 0, len(list))
	for _, b := range list {
		if b != nil {
			wrapped = append(wrapped, httpBackend{b})
		}
	}
	b.selector.Update(wrapped)
}

func (b *Balancer) Snapshot() []*Backend {
	// Return underlying backends
	var result []*Backend
	for _, hb := range b.selector.Backends() {
		if b, ok := hb.(httpBackend); ok {
			result = append(result, b.Backend)
		}
	}
	return result
}

func (b *Balancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	be := b.PickBackend(r)
	if be == nil {
		http.Error(w, "no healthy backends", http.StatusBadGateway)
		return
	}

	ctx := r.Context()
	if b.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.timeout)
		defer cancel()
	}

	be.ServeHTTP(w, r.WithContext(ctx))
}

func (b *Balancer) PickBackend(r *http.Request) *Backend {
	key := b.hashKey(r)
	pick := b.selector.Pick(r, func() uint64 { return key })
	if pick == nil {
		return nil
	}
	if hb, ok := pick.(httpBackend); ok {
		return hb.Backend
	}
	return nil
}

func (b *Balancer) hashKey(r *http.Request) uint64 {
	switch b.selector.Strategy {
	case lb.StrategyIPHash:
		ip := clientip.ClientIP(r)
		return lb.HashString(ip)
	case lb.StrategyURLHash:
		path := r.URL.Path
		if path == "" {
			path = "/"
		}
		return lb.HashString(path)
	default:
		return 0
	}
}
