package xtcp

import (
	"fmt"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
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

	interval := woos.TCPHealthCheckInterval
	timeout := woos.TCPHealthCheckTimeout
	var send, expect string

	if cfg.HealthCheck.Enabled.Active() {
		if cfg.HealthCheck.Interval > 0 {
			interval = cfg.HealthCheck.Interval
		}
		if cfg.HealthCheck.Timeout > 0 {
			timeout = cfg.HealthCheck.Timeout
		}
		send = cfg.HealthCheck.Send
		expect = cfg.HealthCheck.Expect
	} else {
		for _, b := range cfg.Backends {
			if strings.HasSuffix(b.Address, ":6379") {
				send = "PING\r\n"
				expect = "PONG"
				break
			}
		}
	}

	var sendBytes, expectBytes []byte
	if send != "" {
		send = strings.ReplaceAll(send, "\\r", "\r")
		send = strings.ReplaceAll(send, "\\n", "\n")
		sendBytes = []byte(send)
	}
	if expect != "" {
		expectBytes = []byte(expect)
	}

	// Ensure registry is not nil (fallback to global default)
	if registry == nil {
		registry = metrics.DefaultRegistry
	}

	wrappedBackends := make([]lb.Backend, 0, len(cfg.Backends))
	for _, b := range cfg.Backends {
		w := b.Weight
		if w <= 0 {
			w = 1
		}

		// Persistent Stats Key: tcp|<listen>|<sni>|<addr>
		statsKey := fmt.Sprintf("tcp|%s|%s|%s", cfg.Listen, cfg.SNI, b.Address)
		stats := registry.GetOrRegister(statsKey)

		be := &Backend{
			Address:    b.Address,
			Weight:     w,
			MaxConns:   b.MaxConnections,
			hcInterval: interval,
			hcTimeout:  timeout,
			hcSend:     sendBytes,
			hcExpect:   expectBytes,
			failThresh: 2,
			stop:       make(chan struct{}),
			Activity:   stats.Activity,
			Health:     stats.Health,
			Alive:      stats.Alive,
		}

		go be.healthCheckLoop()
		backends = append(backends, be)
		wrappedBackends = append(wrappedBackends, tcpBackend{be})
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
	// Safe to call, returns slice length
	return len(tb.selector.Backends())
}

func (tb *Balancer) GetStrategyName() string {
	return tb.strategyName
}

// Pick selects a backend without re-allocating the selector.
func (tb *Balancer) Pick(exclude map[*Backend]struct{}) *Backend {
	count := tb.BackendCount()
	if count == 0 {
		return nil
	}

	// 1. Fast Path: Try the selector strategy up to 'attempts' times.
	// This respects weights and RR logic without rebuilding the world.
	attempts := min(count, 5)

	// Used for dummy hash keys since we don't have request context in TCP Pick
	dummyKeyFunc := func() uint64 { return 0 }

	for i := 0; i < attempts; i++ {
		// Pass nil request as TCP selection here doesn't access HTTP headers
		candidate := tb.selector.Pick(nil, dummyKeyFunc)
		if candidate == nil {
			continue
		}

		tbBackend, ok := candidate.(tcpBackend)
		if !ok {
			continue
		}

		if tb.isUsable(tbBackend.Backend, exclude) {
			return tbBackend.Backend
		}
	}

	// 2. Slow Path: Linear scan.
	// If the intelligent picker kept hitting excluded nodes, just find *any* healthy one.
	for _, b := range tb.selector.Backends() {
		tbBackend, ok := b.(tcpBackend)
		if !ok {
			continue
		}
		if tb.isUsable(tbBackend.Backend, exclude) {
			return tbBackend.Backend
		}
	}

	return nil
}

func (tb *Balancer) isUsable(b *Backend, exclude map[*Backend]struct{}) bool {
	if b == nil || !b.Alive.Load() {
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
		if tb, ok := b.(tcpBackend); ok {
			result = append(result, tb.Backend)
		}
	}
	return result
}
