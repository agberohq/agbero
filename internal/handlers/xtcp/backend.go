package xtcp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/handlers/upstream"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/olekukonko/ll"
)

type BackendConfig struct {
	Server   alaye.Server
	Proxy    alaye.Proxy
	Resource *resource.Manager
	Logger   *ll.Logger
}

type Backend struct {
	upstream.Base

	stop     chan struct{}
	stopOnce sync.Once
}

func NewBackend(cfg BackendConfig) (*Backend, error) {
	addressStr := cfg.Server.Address.String()
	statsKey := cfg.Proxy.BackendKey(addressStr)

	hasProber := cfg.Proxy.HealthCheck.Enabled.Active() ||
		(cfg.Proxy.HealthCheck.Enabled == alaye.Unknown && (cfg.Proxy.HealthCheck.Send != "" || cfg.Proxy.HealthCheck.Expect != "")) ||
		strings.HasSuffix(addressStr, ":6379")

	baseCfg := upstream.Config{
		Address:        addressStr,
		Weight:         cfg.Server.Weight,
		MaxConnections: cfg.Server.MaxConnections,
		CBThreshold:    2,
		HasProber:      hasProber,
		StatsKey:       statsKey,
		Resource:       cfg.Resource,
	}

	base, err := upstream.NewBase(baseCfg)
	if err != nil {
		return nil, err
	}

	b := &Backend{
		Base: base,
		stop: make(chan struct{}),
	}

	if !hasProber {
		b.HealthScore.Update(health.Record{
			ProbeLatency: 10 * time.Millisecond,
			ProbeSuccess: true,
			ConnHealth:   100,
			PassiveRate:  0,
		})
	}

	if hasProber {
		if err := b.initHealth(cfg); err != nil {
			cfg.Logger.Fields("backend", b.Address, "err", err).Warn("failed to initialize health check")
		}
	}

	return b, nil
}

func (b *Backend) initHealth(cfg BackendConfig) error {
	probeCfg := health.DefaultProbeConfig()
	if cfg.Proxy.HealthCheck.Interval > 0 {
		probeCfg.StandardInterval = cfg.Proxy.HealthCheck.Interval
	}
	if cfg.Proxy.HealthCheck.Timeout > 0 {
		probeCfg.Timeout = cfg.Proxy.HealthCheck.Timeout
	}
	var sendBytes, expectBytes []byte
	if cfg.Proxy.HealthCheck.Send != "" {
		s := strings.ReplaceAll(cfg.Proxy.HealthCheck.Send, "\\r", "\r")
		s = strings.ReplaceAll(s, "\\n", "\n")
		sendBytes = []byte(s)
	}
	if cfg.Proxy.HealthCheck.Expect != "" {
		expectBytes = []byte(cfg.Proxy.HealthCheck.Expect)
	}
	// Use HostPort() helper to strip scheme (e.g., "tcp://host:port" -> "host:port")
	pool := newConnPool(cfg.Server.Address.HostPort(), 3, probeCfg.Timeout)
	executor := &TCPExecutor{
		Pool:   pool,
		Send:   sendBytes,
		Expect: expectBytes,
	}
	return b.RegisterHealth(probeCfg, func(ctx context.Context) error {
		success, latency, err := executor.Probe(ctx)
		b.HealthScore.Update(health.Record{
			ProbeLatency: latency,
			ProbeSuccess: success,
			ConnHealth:   100,
			PassiveRate:  b.HealthScore.PassiveErrorRate(),
		})
		if !success {
			if err != nil {
				return err
			}
			return fmt.Errorf("tcp probe failed")
		}
		return nil
	}, func() {
		pool.close()
	})
}

func (b *Backend) Stop() {
	b.stopOnce.Do(func() {
		close(b.stop)
	})
}

func (b *Backend) Alive() bool {
	return b.Base.Alive()
}

func (b *Backend) Weight() int {
	w := b.Base.Weight()
	if w <= 0 {
		return 1
	}
	return w
}

func (b *Backend) Status(up bool) {
	b.Base.Status(up)
}

func (b *Backend) Snapshot() *Snapshot {
	return &Snapshot{
		Address:     b.Address,
		Alive:       b.Alive(),
		ActiveConns: b.InFlight(),
		Failures:    int64(b.Activity.Failures.Load()),
		MaxConns:    b.MaxConns,
		TotalReqs:   b.Activity.Requests.Load(),
		Latency:     b.Activity.Latency.Snapshot(),
	}
}
