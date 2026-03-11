package xtcp

import (
	mrand "math/rand/v2"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/health"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/lb"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/metrics"
)

type Balancer struct {
	selector      *lb.Selector
	strategyName  string
	proxyProtocol bool
}

func NewBalancer(cfg alaye.TCPRoute, registry *metrics.Registry) *Balancer {
	var backends []*Backend

	if registry == nil {
		registry = metrics.DefaultRegistry
	}

	wrappedBackends := make([]lb.Backend, 0, len(cfg.Backends))
	for _, b := range cfg.Backends {
		w := b.Weight
		if w <= 0 {
			w = 1
		}

		// Deterministic human-readable key
		statsKey := cfg.BackendKey(b.Address)
		stats := registry.GetOrRegister(statsKey)

		// Lookup or initialize the globally managed health score
		hScore := health.GlobalRegistry.GetOrSet(statsKey, health.NewScore(health.DefaultThresholds(), health.DefaultScoringWeights(), health.DefaultLatencyThresholds(), nil))

		hasProber := false
		if cfg.HealthCheck.Enabled.Active() {
			hasProber = true
		} else if cfg.HealthCheck.Enabled == alaye.Unknown && (cfg.HealthCheck.Send != "" || cfg.HealthCheck.Expect != "") {
			hasProber = true
		} else if strings.HasSuffix(b.Address, ":6379") { // Auto-redis ping detection
			hasProber = true
		}

		be := &Backend{
			Address:     b.Address,
			weight:      w,
			MaxConns:    b.MaxConnections,
			failThresh:  2,
			Activity:    stats.Activity,
			HealthScore: hScore,
			Weights:     health.DefaultRoutingMultiplier(),
			hasProber:   hasProber,
			stop:        make(chan struct{}),
		}

		backends = append(backends, be)
		wrappedBackends = append(wrappedBackends, be)
	}

	strategy := lb.ParseStrategy(cfg.Strategy)
	stratName := cfg.Strategy
	if stratName == "" {
		stratName = alaye.StrategyRoundRobin
	}

	return &Balancer{
		selector:      lb.NewSelector(wrappedBackends, strategy),
		strategyName:  stratName,
		proxyProtocol: cfg.ProxyProtocol,
	}
}

func (tb *Balancer) Stop() {
	for _, b := range tb.Backends() {
		if b != nil {
			b.Stop()
		}
	}
}

func (tb *Balancer) BackendCount() int {
	return len(tb.selector.Backends())
}

func (tb *Balancer) GetStrategyName() string {
	return tb.strategyName
}

func (tb *Balancer) Pick(exclude map[*Backend]struct{}) *Backend {
	count := tb.BackendCount()
	if count == 0 {
		return nil
	}

	attempts := min(count, 5)

	for i := 0; i < attempts; i++ {
		keyFunc := func() uint64 {
			return uint64(mrand.Uint32())<<32 | uint64(mrand.Uint32())
		}

		candidate := tb.selector.Pick(nil, keyFunc)
		if candidate == nil {
			continue
		}
		be, ok := candidate.(*Backend)
		if !ok || !tb.isUsable(be, exclude) {
			continue
		}
		return be
	}

	for _, b := range tb.selector.Backends() {
		be, ok := b.(*Backend)
		if !ok || !tb.isUsable(be, exclude) {
			continue
		}
		return be
	}

	return nil
}

func (tb *Balancer) isUsable(b *Backend, exclude map[*Backend]struct{}) bool {
	if b == nil || !b.Alive() {
		return false
	}
	if b.MaxConns > 0 && b.Activity.InFlight.Load() >= b.MaxConns {
		return false
	}
	if _, ok := exclude[b]; ok {
		return false
	}
	return true
}

func (tb *Balancer) useProtocol() bool { return tb != nil && tb.proxyProtocol }

func (tb *Balancer) Backends() []*Backend {
	var result []*Backend
	for _, b := range tb.selector.Backends() {
		if be, ok := b.(*Backend); ok {
			result = append(result, be)
		}
	}
	return result
}
