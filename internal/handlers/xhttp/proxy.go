package xhttp

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/pkg/lb"
	"github.com/cespare/xxhash/v2"
)

type Proxy struct {
	lb        lb.Balancer
	adaptive  *lb.Adaptive
	timeout   time.Duration
	fallback  http.Handler
	ipManager *zulu.IPManager
	keys      []string
}

func NewProxy(cfg ConfigProxy, backends []*Backend, ipManager *zulu.IPManager) *Proxy {
	wrapped := make([]lb.Backend, 0, len(backends))
	for _, b := range backends {
		if b != nil {
			wrapped = append(wrapped, b)
		}
	}
	baseStrat := lb.ParseStrategy(cfg.Strategy)
	baseSelector := lb.NewSelector(wrapped, baseStrat)
	var root lb.Balancer = baseSelector
	var adaptiveRef *lb.Adaptive
	s := strings.ToLower(cfg.Strategy)
	if strings.Contains(s, def.StrategyAdaptive) || strings.Contains(s, def.StrategyLeastResponseTime) {
		adaptiveRef = lb.NewAdaptive(root, 0.15)
		root = adaptiveRef
	}
	if strings.Contains(s, def.StrategySticky) {
		root = lb.NewSticky(root, 30*time.Minute, zulu.Extractor(cfg.Keys))
	}
	// Initialize the balancer with backends so Adaptive has allBackends populated
	root.Update(wrapped)
	return &Proxy{
		lb:        root,
		adaptive:  adaptiveRef,
		timeout:   cfg.Timeout,
		fallback:  cfg.Fallback,
		ipManager: ipManager,
		keys:      cfg.Keys,
	}
}

func (b *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	be := b.Pick(r)
	if be == nil {
		if b.fallback != nil {
			b.fallback.ServeHTTP(w, r)
			return
		}
		http.Error(w, "no healthy backends", http.StatusBadGateway)
		return
	}
	isWebSocket := r.Header.Get("Upgrade") == "websocket"
	ctx := r.Context()
	if b.timeout > 0 && !isWebSocket {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.timeout)
		defer cancel()
	}
	be.ServeHTTP(w, r.WithContext(ctx))
}

func (b *Proxy) Pick(r *http.Request) *Backend {
	keyFunc := func() uint64 {
		ip := b.ipManager.ClientIP(r)
		return xxhash.Sum64String(ip)
	}
	pick := b.lb.Pick(r, keyFunc)
	if pick == nil {
		return nil
	}
	be, ok := pick.(*Backend)
	if !ok {
		return nil
	}
	return be
}

func (b *Proxy) Update(list []*Backend) {
	wrapped := make([]lb.Backend, 0, len(list))
	for _, backend := range list {
		if backend != nil {
			wrapped = append(wrapped, backend)
		}
	}
	b.lb.Update(wrapped)
}

func (b *Proxy) Stop() {
	if b.lb != nil {
		b.lb.Stop()
	}
	if b.adaptive != nil {
		b.adaptive.Stop()
	}

}
