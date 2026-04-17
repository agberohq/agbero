package xudp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/handlers/upstream"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/olekukonko/ll"
)

// BackendConfig carries all parameters needed to construct a UDP backend.
type BackendConfig struct {
	Server   alaye.Server
	Proxy    alaye.Proxy
	Resource *resource.Resource
	Logger   *ll.Logger
}

// Backend is a single UDP upstream target.
// It embeds upstream.Base for activity tracking, health scoring,
// circuit breaker, and metric registration — identical to xtcp.Backend.
type Backend struct {
	upstream.Base

	stop     chan struct{}
	stopOnce sync.Once
}

// NewBackend creates and registers a UDP backend. If a health check is
// configured it is registered with the resource Doctor immediately.
func NewBackend(cfg BackendConfig) (*Backend, error) {
	addressStr := cfg.Server.Address.String()

	// Build the BackendKey with protocol "udp".
	statsKey := alaye.Key{
		Protocol: "udp",
		Domain:   cfg.Proxy.Listen,
		Path:     cfg.Proxy.Name,
		Addr:     addressStr,
	}

	// A backend has a prober when health_check is enabled, or when
	// Send/Expect are set (implicit enable — mirrors xtcp behaviour).
	hasProber := cfg.Proxy.HealthCheck.Enabled.Active() ||
		(cfg.Proxy.HealthCheck.Enabled == expect.Unknown &&
			(!cfg.Proxy.HealthCheck.Send.Empty() || !cfg.Proxy.HealthCheck.Expect.Empty()))

	baseCfg := upstream.Config{
		Address:        addressStr,
		Weight:         cfg.Server.Weight,
		MaxConnections: cfg.Server.MaxConnections,
		CBThreshold:    2, // circuit-break after 2 consecutive failures
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

	// Without a prober, seed health score as healthy so the backend is
	// immediately usable — same as xtcp.
	if !hasProber {
		b.HealthScore.Update(health.Record{
			ProbeLatency: 10 * time.Millisecond,
			ProbeSuccess: true,
			ConnHealth:   100,
			PassiveRate:  0,
		})
	} else {
		if err := b.initHealth(cfg); err != nil {
			cfg.Logger.Fields("backend", b.Address, "err", err).
				Warn("xudp: failed to initialize health check")
		}
	}

	return b, nil
}

// initHealth registers the health probe with the resource Doctor.
func (b *Backend) initHealth(cfg BackendConfig) error {
	probeCfg := health.DefaultProbeConfig()
	if cfg.Proxy.HealthCheck.Interval > 0 {
		probeCfg.StandardInterval = cfg.Proxy.HealthCheck.Interval.StdDuration()
	}
	if cfg.Proxy.HealthCheck.Timeout > 0 {
		probeCfg.Timeout = cfg.Proxy.HealthCheck.Timeout.StdDuration()
	}

	// Unescape \r\n sequences in the Send/Expect strings, consistent
	// with how xtcp handles them.
	var sendBytes, expectBytes []byte
	if !cfg.Proxy.HealthCheck.Send.Empty() {
		s := strings.ReplaceAll(cfg.Proxy.HealthCheck.Send.Get(), `\r`, "\r")
		s = strings.ReplaceAll(s, `\n`, "\n")
		sendBytes = []byte(s)
	}
	if !cfg.Proxy.HealthCheck.Expect.Empty() {
		expectBytes = []byte(cfg.Proxy.HealthCheck.Expect)
	}

	executor := &UDPExecutor{
		Address: cfg.Server.Address.HostPort(),
		Send:    sendBytes,
		Expect:  expectBytes,
		Timeout: probeCfg.Timeout,
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
			return fmt.Errorf("udp probe failed")
		}
		return nil
	}, nil)
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

// Snapshot returns a point-in-time health/metrics snapshot for this backend.
// Used by the uptime handler.
func (b *Backend) Snapshot() *Snapshot {
	return &Snapshot{
		Address:     b.Address,
		Alive:       b.Alive(),
		ActiveSess:  b.InFlight(),
		Failures:    int64(b.Activity.Failures.Load()),
		MaxSessions: b.MaxConns,
		TotalReqs:   b.Activity.Requests.Load(),
		Latency:     b.Activity.Latency.Snapshot(),
	}
}
