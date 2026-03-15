package resource

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/agberohq/agbero/internal/pkg/metrics"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/mappo"
)

type Option func(*Manager)

func WithLogger(logger *ll.Logger) Option {
	return func(m *Manager) {
		m.Logger = logger
	}
}

func WithShutdown(shutdown *jack.Shutdown) Option {
	return func(m *Manager) {
		m.Shutdown = shutdown
	}
}

func WithReaper(reapHandler func(context.Context, string)) Option {
	return func(m *Manager) {
		if m.Reaper != nil {
			m.Reaper.Stop()
		}

		if reapHandler != nil {
			m.Reaper = jack.NewReaper(
				woos.RouteCacheTTL,
				jack.ReaperWithLogger(m.Logger),
				jack.ReaperWithHandler(reapHandler),
			)
			m.Reaper.Start()
		}
	}
}

func WithCustomTransport(transport *http.Transport) Option {
	return func(m *Manager) {
		m.Transport = transport
		if m.HTTPClient != nil && m.HTTPClient.Transport == m.Transport {
			m.HTTPClient.Transport = transport
		}
	}
}

func WithCustomHTTPClient(client *http.Client) Option {
	return func(m *Manager) {
		m.HTTPClient = client
	}
}

func WithDoctor(doctor *jack.Doctor) Option {
	return func(m *Manager) {
		if m.Doctor != nil {
			m.Doctor.StopAll(2 * time.Second)
		}
		m.Doctor = doctor
	}
}

func WithLifetimeManager(lm *jack.Lifetime) Option {
	return func(m *Manager) {
		if m.Lifetime != nil {
			m.Lifetime.Stop()
		}
		m.Lifetime = lm
	}
}

func WithCacheSizes(routeMax, tcpMax, authMax, gzMax int) Option {
	return func(m *Manager) {
		if routeMax > 0 {
			oldCache := m.RouteCache
			m.RouteCache = mappo.NewCache(mappo.CacheOptions{MaximumSize: routeMax, OnDelete: mappo.CloserDelete})
			if oldCache != nil {
				oldCache.Clear()
			}
		}
		if tcpMax > 0 {
			oldCache := m.TCPCache
			m.TCPCache = mappo.NewCache(mappo.CacheOptions{MaximumSize: tcpMax, OnDelete: mappo.CloserDelete})
			if oldCache != nil {
				oldCache.Clear()
			}
		}
		if authMax > 0 {
			oldCache := m.AuthCache
			m.AuthCache = mappo.NewCache(mappo.CacheOptions{MaximumSize: authMax, OnDelete: mappo.CloserDelete})
			if oldCache != nil {
				oldCache.Clear()
			}
		}
		if gzMax > 0 {
			oldCache := m.GzCache
			m.GzCache = mappo.NewCache(mappo.CacheOptions{MaximumSize: gzMax})
			if oldCache != nil {
				oldCache.Clear()
			}
		}
	}
}

func WithMetrics(registry *metrics.Registry) Option {
	return func(m *Manager) {
		oldMetrics := m.Metrics
		m.Metrics = registry
		if oldMetrics != nil {
			oldMetrics.Clear()
		}
	}
}

func WithHealth(registry *health.Registry) Option {
	return func(m *Manager) {
		oldHealth := m.Health
		m.Health = registry
		if oldHealth != nil {
			oldHealth.Clear()
		}
	}
}

func WithRouteCache(cache *mappo.Cache) Option {
	return func(m *Manager) {
		oldCache := m.RouteCache
		m.RouteCache = cache
		if oldCache != nil {
			oldCache.Clear()
		}
	}
}

func WithTCPCache(cache *mappo.Cache) Option {
	return func(m *Manager) {
		oldCache := m.TCPCache
		m.TCPCache = cache
		if oldCache != nil {
			oldCache.Clear()
		}
	}
}

func WithAuthCache(cache *mappo.Cache) Option {
	return func(m *Manager) {
		oldCache := m.AuthCache
		m.AuthCache = cache
		if oldCache != nil {
			oldCache.Clear()
		}
	}
}

func WithGzCache(cache *mappo.Cache) Option {
	return func(m *Manager) {
		oldCache := m.GzCache
		m.GzCache = cache
		if oldCache != nil {
			oldCache.Clear()
		}
	}
}

type Manager struct {
	Metrics    *metrics.Registry
	Health     *health.Registry
	RouteCache *mappo.Cache
	TCPCache   *mappo.Cache
	AuthCache  *mappo.Cache
	GzCache    *mappo.Cache

	Transport  *http.Transport
	HTTPClient *http.Client

	Logger   *ll.Logger
	Doctor   *jack.Doctor
	Reaper   *jack.Reaper
	Shutdown *jack.Shutdown
	Lifetime *jack.Lifetime
	Janitor  *jack.Pool

	// internal
	counter *atomic.Uint64
}

func New(opts ...Option) *Manager {
	m := &Manager{
		Metrics:    metrics.NewRegistry(),
		Health:     health.NewRegistry(),
		RouteCache: mappo.NewCache(mappo.CacheOptions{MaximumSize: woos.CacheMax, OnDelete: mappo.CloserDelete}),
		TCPCache:   mappo.NewCache(mappo.CacheOptions{MaximumSize: woos.CacheMax, OnDelete: mappo.CloserDelete}),
		AuthCache:  mappo.NewCache(mappo.CacheOptions{MaximumSize: woos.CacheMaxBig, OnDelete: mappo.CloserDelete}),
		GzCache:    mappo.NewCache(mappo.CacheOptions{MaximumSize: woos.CacheMax}),
	}

	m.setDefaults()
	m.Apply(opts...)

	return m
}

func (m *Manager) Apply(opts ...Option) {
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}
}

func (m *Manager) setDefaults() {
	if m.Logger == nil {
		m.Logger = ll.New("agbero").Disable()
	}

	if m.Transport == nil {
		m.Transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   woos.DefaultTransportDialTimeout,
				KeepAlive: woos.DefaultTransportKeepAlive,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          woos.DefaultTransportMaxIdleConns,
			MaxIdleConnsPerHost:   woos.DefaultTransportMaxIdleConnsPerHost,
			IdleConnTimeout:       woos.DefaultTransportIdleConnTimeout,
			TLSHandshakeTimeout:   woos.DefaultTransportTLSHandshakeTimeout,
			ResponseHeaderTimeout: woos.DefaultTransportResponseHeaderTimeout,
			ExpectContinueTimeout: 0,
		}
	}

	if m.HTTPClient == nil {
		m.HTTPClient = &http.Client{
			Timeout:   5 * time.Second,
			Transport: m.Transport,
		}
	}

	if m.Doctor == nil {
		m.Doctor = jack.NewDoctor(jack.DoctorWithLogger(m.Logger))
	}

	if m.Lifetime == nil {
		m.Lifetime = jack.NewLifetime(
			jack.LifetimeWithLogger(m.Logger),
			jack.LifetimeWithShards(32),
		)
	}

	if m.Janitor == nil {
		m.Janitor = jack.NewPool(2, jack.PoolingWithQueueSize(10000))
	}
}

func (m *Manager) Validate() error {
	if m.Metrics == nil {
		return errors.New("resource.metrics registry required")
	}
	if m.Health == nil {
		return errors.New("resource.health store required")
	}
	if m.Transport == nil {
		return errors.New("resource.transport required")
	}
	if m.HTTPClient == nil {
		return errors.New("resource.http_client required")
	}
	return nil
}

func (m *Manager) Close() {
	// Step 1: Shutdown the janitor pool first - this prevents new submissions
	if m.Janitor != nil {
		_ = m.Janitor.Shutdown(2 * time.Second)
	}

	// Step 2: Now stop other components that might submit to the pool
	if m.Lifetime != nil {
		m.Lifetime.Stop()
	}
	if m.Reaper != nil {
		m.Reaper.Stop()
	}
	if m.Doctor != nil {
		m.Doctor.StopAll(2 * time.Second)
	}

	// Step 3: Clear caches - these may trigger callbacks but the pool is already shut down
	m.Metrics.Clear()
	m.Health.Clear()
	m.RouteCache.Clear()
	m.TCPCache.Clear()
	m.AuthCache.Clear()
	m.GzCache.Clear()

	// Step 4: Clean up remaining resources
	m.Transport.CloseIdleConnections()
}

// Counter returns the current value without incrementing (if needed)
func (m *Manager) Counter() uint64 {
	return m.counter.Load()
}

// NextID increments and returns the next ID - HOT PATH
//
//go:nosplit
func (m *Manager) NextID() uint64 {
	return m.counter.Add(1)
}
