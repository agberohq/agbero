package xhttp

import (
	"context"
	"net/http"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/lb"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

// Balancer wraps the core/lb logic for HTTP backends, handling strategy composition.
type Balancer struct {
	lb          lb.Balancer
	adaptive    *lb.Adaptive
	timeout     time.Duration
	stripPrefix []string
	strategy    string
}

// NewBalancer creates a configured balancer chain (Selector -> Adaptive -> Sticky).
func NewBalancer(backends []*Backend, strategy string, timeout time.Duration, stripPrefixes []string) *Balancer {
	wrapped := make([]lb.Backend, 0, len(backends))
	for _, b := range backends {
		if b != nil {
			wrapped = append(wrapped, httpBackend{b})
		}
	}

	baseStrat := lb.ParseStrategy(strategy)
	baseSelector := lb.NewSelector(wrapped, baseStrat)

	var root lb.Balancer = baseSelector
	var adaptiveRef *lb.Adaptive

	s := strings.ToLower(strategy)

	if strings.Contains(s, alaye.StrategyAdaptive) {
		adaptiveRef = lb.NewAdaptive(root, 0.15)
		root = adaptiveRef
	}

	if strings.Contains(s, alaye.StrategySticky) {
		extractor := func(r *http.Request) string {
			if c, err := r.Cookie(woos.SessionCookieName); err == nil {
				return c.Value
			}
			return clientip.ClientIP(r)
		}
		root = lb.NewSticky(root, 30*time.Minute, extractor)
	}

	return &Balancer{
		lb:          root,
		adaptive:    adaptiveRef,
		timeout:     timeout,
		stripPrefix: append([]string(nil), stripPrefixes...),
		strategy:    strategy,
	}
}

// Update refreshes the backend list across the entire balancer chain.
func (b *Balancer) Update(list []*Backend) {
	wrapped := make([]lb.Backend, 0, len(list))
	for _, backend := range list {
		if backend != nil {
			wrapped = append(wrapped, httpBackend{backend})
		}
	}
	b.lb.Update(wrapped)
}

// ServeHTTP handles the request lifecycle including backend selection, timeouts, and metric recording.
func (b *Balancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	be := b.Pick(r)
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

	start := time.Now()
	be.ServeHTTP(w, r.WithContext(ctx))

	if b.adaptive != nil {
		latency := time.Since(start).Microseconds()
		failed := false
		if latency > b.timeout.Microseconds() && b.timeout > 0 {
			failed = true
		}
		b.adaptive.RecordResult(httpBackend{be}, latency, failed)
	}
}

// Pick selects a concrete Backend using the configured load balancing chain.
func (b *Balancer) Pick(r *http.Request) *Backend {
	pick := b.lb.Pick(r, func() uint64 { return b.hashKey(r) })

	if pick == nil {
		return nil
	}
	if hb, ok := pick.(httpBackend); ok {
		return hb.Backend
	}
	return nil
}

// hashKey generates a consistent hash key for IP/URL strategies.
func (b *Balancer) hashKey(r *http.Request) uint64 {
	if strings.Contains(b.strategy, alaye.StrategyIPHash) || strings.Contains(b.strategy, alaye.StrategyConsistentHash) {
		ip := clientip.ClientIP(r)
		return lb.HashString(ip)
	}
	if strings.Contains(b.strategy, alaye.StrategyURLHash) {
		path := r.URL.Path
		if path == "" {
			path = "/"
		}
		return lb.HashString(path)
	}
	return 0
}
