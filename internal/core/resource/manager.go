package resource

import (
	"context"
	"net"
	"net/http"
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

// WithLogger sets the logger
func WithLogger(logger *ll.Logger) Option {
	return func(m *Manager) {
		m.Logger = logger
	}
}

// WithShutdown sets the shutdown handler
func WithShutdown(shutdown *jack.Shutdown) Option {
	return func(m *Manager) {
		m.Shutdown = shutdown
	}
}

// WithReaper sets up a reaper with the provided handler
func WithReaper(reapHandler func(context.Context, string)) Option {
	return func(m *Manager) {
		// Stop existing reaper if any
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

// WithCustomTransport allows overriding the default HTTP transport
func WithCustomTransport(transport *http.Transport) Option {
	return func(m *Manager) {
		m.Transport = transport
		// Update HTTP client if it exists and uses the default transport
		if m.HTTPClient != nil && m.HTTPClient.Transport == m.Transport {
			m.HTTPClient.Transport = transport
		}
	}
}

// WithCustomHTTPClient allows overriding the default HTTP client
func WithCustomHTTPClient(client *http.Client) Option {
	return func(m *Manager) {
		m.HTTPClient = client
	}
}

// WithDoctor allows overriding the default doctor
func WithDoctor(doctor *jack.Doctor) Option {
	return func(m *Manager) {
		// Stop existing doctor if any
		if m.Doctor != nil {
			m.Doctor.StopAll(2 * time.Second)
		}
		m.Doctor = doctor
	}
}

// WithLifetimeManager allows overriding the default lifetime manager
func WithLifetimeManager(lm *jack.LifetimeManager) Option {
	return func(m *Manager) {
		// Stop existing lifetime manager if any
		if m.Lifetime != nil {
			m.Lifetime.Stop()
		}
		m.Lifetime = lm
	}
}

// WithCacheSizes allows customizing cache sizes
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

// WithMetrics allows overriding the metrics registry
func WithMetrics(registry *metrics.Registry) Option {
	return func(m *Manager) {
		oldMetrics := m.Metrics
		m.Metrics = registry
		if oldMetrics != nil {
			oldMetrics.Clear()
		}
	}
}

// WithHealth allows overriding the health registry
func WithHealth(registry *health.Registry) Option {
	return func(m *Manager) {
		oldHealth := m.Health
		m.Health = registry
		if oldHealth != nil {
			oldHealth.Clear()
		}
	}
}

// WithRouteCache allows setting a custom route cache
func WithRouteCache(cache *mappo.Cache) Option {
	return func(m *Manager) {
		oldCache := m.RouteCache
		m.RouteCache = cache
		if oldCache != nil {
			oldCache.Clear()
		}
	}
}

// WithTCPCache allows setting a custom TCP cache
func WithTCPCache(cache *mappo.Cache) Option {
	return func(m *Manager) {
		oldCache := m.TCPCache
		m.TCPCache = cache
		if oldCache != nil {
			oldCache.Clear()
		}
	}
}

// WithAuthCache allows setting a custom auth cache
func WithAuthCache(cache *mappo.Cache) Option {
	return func(m *Manager) {
		oldCache := m.AuthCache
		m.AuthCache = cache
		if oldCache != nil {
			oldCache.Clear()
		}
	}
}

// WithGzCache allows setting a custom gzip cache
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
	Lifetime *jack.LifetimeManager
}

// New creates a new Manager with the provided options
func New(opts ...Option) *Manager {
	// Create manager with defaults
	m := &Manager{
		Metrics:    metrics.NewRegistry(),
		Health:     health.NewRegistry(),
		RouteCache: mappo.NewCache(mappo.CacheOptions{MaximumSize: woos.CacheMax, OnDelete: mappo.CloserDelete}),
		TCPCache:   mappo.NewCache(mappo.CacheOptions{MaximumSize: woos.CacheMax, OnDelete: mappo.CloserDelete}),
		AuthCache:  mappo.NewCache(mappo.CacheOptions{MaximumSize: woos.CacheMaxBig, OnDelete: mappo.CloserDelete}),
		GzCache:    mappo.NewCache(mappo.CacheOptions{MaximumSize: woos.CacheMax}),
	}

	// Set defaults before applying options
	m.setDefaults()

	// Apply all options
	m.Apply(opts...)

	return m
}

// Apply applies the provided options to the Manager
func (m *Manager) Apply(opts ...Option) {
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}
}

// setDefaults initializes default values for nil fields
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
		m.Lifetime = jack.NewLifetimeManager(
			jack.LifetimeManagerWithLogger(m.Logger),
			jack.LifetimeManagerWithShards(32),
		)
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
	m.Metrics.Clear()
	m.Health.Clear()
	m.RouteCache.Clear()
	m.TCPCache.Clear()
	m.AuthCache.Clear()
	m.GzCache.Clear()
	m.Transport.CloseIdleConnections()

	if m.Doctor != nil {
		m.Doctor.StopAll(2 * time.Second)
	}
	if m.Reaper != nil {
		m.Reaper.Stop()
	}
	if m.Lifetime != nil {
		m.Lifetime.Stop()
	}
}
