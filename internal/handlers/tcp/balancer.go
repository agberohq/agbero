package tcp

import (
	"math/rand"
	"strings"
	"sync/atomic"

	"git.imaxinacion.net/aibox/agbero/internal/core/metrics"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

type Balancer struct {
	backends     []*Backend
	strategy     uint8
	strategyName string // Store string representation for Uptime

	rrCounter     atomic.Uint64
	proxyProtocol bool
}

func NewBalancer(cfg alaye.TCPRoute) *Balancer {
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
		// Smart defaults for Redis, etc.
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

	for _, b := range cfg.Backends {
		w := b.Weight
		if w <= 0 {
			w = 1
		}

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
			Activity:   metrics.NewActivityTracker(),
			Health:     metrics.NewHealthTracker(),
		}
		be.Alive.Store(true)
		go be.healthCheckLoop()
		backends = append(backends, be)
	}

	strat := woos.StRoundRobin
	stratName := alaye.StrategyRoundRobin

	switch strings.ToLower(strings.TrimSpace(cfg.Strategy)) {
	case "least_conn":
		strat = woos.StLeastConn
		stratName = alaye.StrategyLeastConn
	case "random":
		strat = woos.StRandom
		stratName = alaye.StrategyRandom
	}

	return &Balancer{
		backends:      backends,
		strategy:      strat,
		strategyName:  stratName,
		proxyProtocol: cfg.ProxyProtocol,
	}
}

func (tb *Balancer) Stop() {
	for _, b := range tb.backends {
		if b != nil {
			b.Stop()
		}
	}
}

func (tb *Balancer) BackendCount() int {
	return len(tb.backends)
}

func (tb *Balancer) GetStrategyName() string {
	return tb.strategyName
}

func (tb *Balancer) Pick(exclude map[*Backend]struct{}) *Backend {
	if len(tb.backends) == 0 {
		return nil
	}
	if len(tb.backends) == 1 {
		b := tb.backends[0]
		if b != nil && b.Alive.Load() {
			if b.MaxConns > 0 && b.Activity.InFlight.Load() >= b.MaxConns {
				return nil
			}
			if _, ok := exclude[b]; !ok {
				return b
			}
		}
		return nil
	}

	switch tb.strategy {
	case woos.StLeastConn:
		return tb.pickLeastConn(exclude)
	case woos.StRandom:
		return tb.pickRandom(exclude)
	default:
		return tb.pickRoundRobin(exclude)
	}
}

func (tb *Balancer) pickRoundRobin(exclude map[*Backend]struct{}) *Backend {
	n := uint64(len(tb.backends))
	if n == 0 {
		return nil
	}

	// Fix Integer Overflow:
	// We only care about the offset relative to n.
	raw := tb.rrCounter.Add(1)
	start := int(raw % n)

	for i := 0; i < len(tb.backends); i++ {
		idx := (start + i) % len(tb.backends)
		b := tb.backends[idx]
		if !tb.isUsable(b, exclude) {
			continue
		}
		return b
	}
	return nil
}

func (tb *Balancer) pickRandom(exclude map[*Backend]struct{}) *Backend {
	r := rngPool.Get().(*rand.Rand)
	start := r.Intn(len(tb.backends))
	rngPool.Put(r)

	n := len(tb.backends)
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		b := tb.backends[idx]
		if !tb.isUsable(b, exclude) {
			continue
		}
		return b
	}
	return nil
}

func (tb *Balancer) pickLeastConn(exclude map[*Backend]struct{}) *Backend {
	var best *Backend
	var min int64 = -1

	for _, b := range tb.backends {
		if !tb.isUsable(b, exclude) {
			continue
		}

		c := b.Activity.InFlight.Load()
		if min == -1 || c < min {
			min = c
			best = b
		}
	}
	return best
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
	return tb.backends
}
