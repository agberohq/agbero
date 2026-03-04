package xhttp

import (
	"context"
	"net/http"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/lb"
)

type Balancer struct {
	lb       lb.Balancer
	adaptive *lb.Adaptive
	timeout  time.Duration
	strategy string
	fallback http.Handler
}

// NewBalancer accepts a Config object and the list of backends.
// The stripPrefix logic is removed from here as it is now handled by middleware.
func NewBalancer(cfg Config, backends []*Backend) *Balancer {
	wrapped := make([]lb.Backend, 0, len(backends))
	for _, b := range backends {
		if b != nil {
			wrapped = append(wrapped, httpBackend{b})
		}
	}

	baseStrat := lb.ParseStrategy(cfg.Strategy)
	baseSelector := lb.NewSelector(wrapped, baseStrat)

	var root lb.Balancer = baseSelector
	var adaptiveRef *lb.Adaptive

	s := strings.ToLower(cfg.Strategy)

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
		lb:       root,
		adaptive: adaptiveRef,
		timeout:  cfg.Timeout,
		strategy: cfg.Strategy,
		fallback: cfg.Fallback,
	}
}

func (b *Balancer) Update(list []*Backend) {
	wrapped := make([]lb.Backend, 0, len(list))
	for _, backend := range list {
		if backend != nil {
			wrapped = append(wrapped, httpBackend{backend})
		}
	}
	b.lb.Update(wrapped)
}

func (b *Balancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	be := b.Pick(r)
	if be == nil {
		if b.fallback != nil {
			b.fallback.ServeHTTP(w, r)
			return
		}
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
