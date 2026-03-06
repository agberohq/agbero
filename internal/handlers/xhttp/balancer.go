package xhttp

import (
	"context"
	"net/http"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/lb"
)

type Balancer struct {
	lb        lb.Balancer
	adaptive  *lb.Adaptive
	timeout   time.Duration
	fallback  http.Handler
	ipManager *zulu.IPManager
	keys      []string
}

func NewBalancer(cfg ConfigBalancer, backends []*Backend, ipManager *zulu.IPManager) *Balancer {
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

	if strings.Contains(s, alaye.StrategyAdaptive) || strings.Contains(s, alaye.StrategyLeastResponseTime) {
		adaptiveRef = lb.NewAdaptive(root, 0.15)
		root = adaptiveRef
	}

	if strings.Contains(s, alaye.StrategySticky) {
		root = lb.NewSticky(root, 30*time.Minute, zulu.Extractor(cfg.Keys))
	}

	return &Balancer{
		lb:        root,
		adaptive:  adaptiveRef,
		timeout:   cfg.Timeout,
		fallback:  cfg.Fallback,
		ipManager: ipManager,
		keys:      cfg.Keys,
	}
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

	isWebSocket := r.Header.Get("Upgrade") == "websocket"

	ctx := r.Context()
	if b.timeout > 0 && !isWebSocket {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.timeout)
		defer cancel()
	}

	start := time.Now()
	be.ServeHTTP(w, r.WithContext(ctx))

	if b.adaptive != nil {
		latency := time.Since(start).Microseconds()
		failed := false

		if !isWebSocket && b.timeout > 0 && latency > b.timeout.Microseconds() {
			failed = true
		}
		b.adaptive.RecordResult(be, latency, failed)
	}
}

func (b *Balancer) Pick(r *http.Request) *Backend {
	hashFunc := func() uint64 {
		key := ""
		if len(b.keys) == 0 {
			if b.ipManager != nil {
				key = b.ipManager.ClientIP(r)
			} else {
				key = r.RemoteAddr
			}
		} else {
			for _, k := range b.keys {
				val := ""
				switch {
				case strings.HasPrefix(k, "cookie:"):
					name := k[7:]
					if c, err := r.Cookie(name); err == nil {
						val = c.Value
					}
				case strings.HasPrefix(k, "header:"):
					name := k[7:]
					val = r.Header.Get(name)
				case strings.HasPrefix(k, "query:"):
					name := k[6:]
					val = r.URL.Query().Get(name)
				case k == "ip":
					if b.ipManager != nil {
						val = b.ipManager.ClientIP(r)
					} else {
						val = r.RemoteAddr
					}
				}
				if val != "" {
					key = val
					break
				}
			}
		}

		if key == "" {
			return 0
		}
		return lb.HashString(key)
	}

	pick := b.lb.Pick(r, hashFunc)

	if pick == nil {
		return nil
	}
	if be, ok := pick.(*Backend); ok {
		return be
	}
	return nil
}

func (b *Balancer) Update(list []*Backend) {
	wrapped := make([]lb.Backend, 0, len(list))
	for _, backend := range list {
		if backend != nil {
			wrapped = append(wrapped, backend)
		}
	}
	b.lb.Update(wrapped)
}
