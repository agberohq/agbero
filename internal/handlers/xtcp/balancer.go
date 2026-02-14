// xtcp/balancer.go - Complete rewrite using new balancer package
package xtcp

import (
	"fmt"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/core/balancer"
	"git.imaxinacion.net/aibox/agbero/internal/core/metrics"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

// tcpBackend wraps xtcp.Backend to implement balancer.Backend interface
type tcpBackend struct {
	*Backend
}

func (b tcpBackend) Alive() bool     { return b.Backend.Alive.Load() }
func (b tcpBackend) Weight() int     { return b.Backend.Weight }
func (b tcpBackend) InFlight() int64 { return b.Backend.Activity.InFlight.Load() }
func (b tcpBackend) ResponseTime() int64 {
	snap := b.Backend.Activity.Latency.Snapshot()
	if snap.Count == 0 {
		return 0
	}
	return snap.Avg // Changed from Mean to Avg
}

type Balancer struct {
	selector      *balancer.Selector
	strategyName  string
	proxyProtocol bool
}

func NewBalancer(cfg alaye.TCPRoute, registry *metrics.Registry) *Balancer {
	var backends []*Backend

	interval := woos.TCPHealthCheckInterval
	timeout := woos.TCPHealthCheckTimeout
	var send, expect string

	if cfg.HealthCheck != nil {
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

	wrappedBackends := make([]balancer.Backend, 0, len(cfg.Backends))
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

	strategy := balancer.ParseStrategy(cfg.Strategy)
	stratName := cfg.Strategy
	if stratName == "" {
		stratName = alaye.StrategyRoundRobin
	}

	return &Balancer{
		selector:      balancer.NewSelector(wrappedBackends, strategy),
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
	backends := tb.selector.Backends()
	if len(backends) == 0 {
		return nil
	}

	// Filter out excluded and unusable backends
	var candidates []balancer.Backend
	for _, b := range backends {
		tb := b.(tcpBackend)
		if tb.Backend == nil || !tb.Backend.Alive.Load() {
			continue
		}
		if tb.Backend.MaxConns > 0 && tb.Backend.Activity.InFlight.Load() >= tb.Backend.MaxConns {
			continue
		}
		if _, ok := exclude[tb.Backend]; ok {
			continue
		}
		candidates = append(candidates, b)
	}

	if len(candidates) == 0 {
		return nil
	}

	// Use selector's strategy on filtered candidates
	// Create a temporary selector with just candidates
	tempSelector := balancer.NewSelector(candidates, tb.selector.Strategy)

	// For strategies that need request info, we pass nil
	selected := tempSelector.Pick(nil, func() uint64 { return 0 })
	if selected == nil {
		return nil
	}
	return selected.(tcpBackend).Backend
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
