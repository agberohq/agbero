// Package resource coordinates long-lived system components and shared state.
// It manages the lifecycle of caches, metrics, health registries, and environment variables.
package resource

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/agberohq/agbero/internal/pkg/metrics"
	"github.com/agberohq/keeper"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/mappo"
)

type Option func(*Resource)

// WithLogger sets the system-wide logger for the resource manager.
// It allows for namespaced logging across all managed proxy components.
func WithLogger(logger *ll.Logger) Option {
	return func(m *Resource) {
		m.Logger = logger
	}
}

// WithShutdown configures the global shutdown manager for the resource.
// It ensures that all registered cleanup functions are executed on exit.
func WithShutdown(shutdown *jack.Shutdown) Option {
	return func(m *Resource) {
		m.Shutdown = shutdown
	}
}

// WithReaper initializes the cache reaper with a custom cleanup handler.
// It automatically removes expired entries from the route and auth caches.
func WithReaper(reapHandler func(context.Context, string)) Option {
	return func(m *Resource) {
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

// WithCustomTransport sets a specialized HTTP transport for backend proxying.
// It is primarily used to tune connection pooling and timeout behavior.
func WithCustomTransport(transport *http.Transport) Option {
	return func(m *Resource) {
		m.Transport = transport
		if m.HTTPClient != nil && m.HTTPClient.Transport == m.Transport {
			m.HTTPClient.Transport = transport
		}
	}
}

// WithCustomHTTPClient assigns a pre-configured HTTP client to the resource manager.
// This client is used for all outgoing requests including auth and serverless REST.
func WithCustomHTTPClient(client *http.Client) Option {
	return func(m *Resource) {
		m.HTTPClient = client
	}
}

// WithDoctor attaches a health monitor to track the status of backend patients.
// It ensures that background health checks are executed according to their interval.
func WithDoctor(doctor *jack.Doctor) Option {
	return func(m *Resource) {
		if m.Doctor != nil {
			m.Doctor.StopAll(2 * time.Second)
		}
		m.Doctor = doctor
	}
}

// WithLifetimeManager configures the TTL manager for dynamic cluster resources.
// It tracks the expiration of temporary routes and security tokens.
func WithLifetimeManager(lm *jack.Lifetime) Option {
	return func(m *Resource) {
		if m.Lifetime != nil {
			m.Lifetime.Stop()
		}
		m.Lifetime = lm
	}
}

// WithCacheSizes reinitializes internal caches with the specified maximum capacities.
// It clears existing data to ensure the new size constraints are applied immediately.
func WithCacheSizes(routeMax, tcpMax, authMax, gzMax int) Option {
	return func(m *Resource) {
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

// WithMetrics replaces the current metrics registry with a new instance.
// This is used during reloads to reset or reconfigure telemetry collection.
func WithMetrics(registry *metrics.Registry) Option {
	return func(m *Resource) {
		oldMetrics := m.Metrics
		m.Metrics = registry
		if oldMetrics != nil {
			oldMetrics.Clear()
		}
	}
}

// WithHealth replaces the current backend health registry.
// It allows for fresh health score tracking during configuration updates.
func WithHealth(registry *health.Registry) Option {
	return func(m *Resource) {
		oldHealth := m.Health
		m.Health = registry
		if oldHealth != nil {
			oldHealth.Clear()
		}
	}
}

// WithRouteCache sets a specific cache instance for HTTP route lookup results.
// It ensures that high-frequency route matching remains performant under load.
func WithRouteCache(cache *mappo.Cache) Option {
	return func(m *Resource) {
		oldCache := m.RouteCache
		m.RouteCache = cache
		if oldCache != nil {
			oldCache.Clear()
		}
	}
}

// WithTCPCache sets a specific cache instance for TCP stream mapping results.
// This provides rapid lookup for SNI and port-based connection routing.
func WithTCPCache(cache *mappo.Cache) Option {
	return func(m *Resource) {
		oldCache := m.TCPCache
		m.TCPCache = cache
		if oldCache != nil {
			oldCache.Clear()
		}
	}
}

// WithAuthCache sets the cache used for storing successful authentication results.
// It reduces the load on external auth providers by caching tokens and session state.
func WithAuthCache(cache *mappo.Cache) Option {
	return func(m *Resource) {
		oldCache := m.AuthCache
		m.AuthCache = cache
		if oldCache != nil {
			oldCache.Clear()
		}
	}
}

// WithGzCache sets the cache instance for pre-compressed static content.
// It allows the server to serve gzipped payloads without re-compressing them.
func WithGzCache(cache *mappo.Cache) Option {
	return func(m *Resource) {
		oldCache := m.GzCache
		m.GzCache = cache
		if oldCache != nil {
			oldCache.Clear()
		}
	}
}

// WithLifetime sets the Lifetime field of a Resource to the provided Lifetime instance.
func WithLifetime(l *jack.Lifetime) Option {
	return func(h *Resource) {
		h.Lifetime = l
	}
}

// WithKeeper sets the Keeper instance for the Resource, allowing it to manage and coordinate subsystem operations.
func WithKeeper(k *keeper.Keeper) Option {
	return func(m *Resource) {
		m.Keeper = k
	}
}

type Env struct {
	mu     sync.RWMutex
	Global *mappo.Concurrent[string, expect.Value]
	Route  *mappo.Concurrent[string, expect.Value]
}

// GetGlobal safely retrieves the current global env map pointer
func (e *Env) GetGlobal() *mappo.Concurrent[string, expect.Value] {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.Global
}

// UpdateGlobal creates a new concurrent map, populates it,
// and safely swaps the pointer so readers never see partial state.
func (m *Resource) UpdateGlobal(newEnv map[string]expect.Value) {
	newGlobal := mappo.NewConcurrent[string, expect.Value]()
	for k, v := range newEnv {
		newGlobal.Set(k, v)
	}

	// Perform the pointer swap safely
	m.Env.mu.Lock()
	m.Env.Global = newGlobal
	m.Env.mu.Unlock()
}

type Resource struct {
	Metrics    *metrics.Registry
	Health     *health.Registry
	RouteCache *mappo.Cache
	TCPCache   *mappo.Cache
	AuthCache  *mappo.Cache
	GzCache    *mappo.Cache

	TimeStore *mappo.Concurrent[string, time.Time]

	Transport  *http.Transport
	HTTPClient *http.Client

	Logger     *ll.Logger
	Doctor     *jack.Doctor
	Reaper     *jack.Reaper
	Shutdown   *jack.Shutdown
	Lifetime   *jack.Lifetime
	Keeper     *keeper.Keeper
	Janitor    *jack.Pool
	Background *jack.Pool

	Env *Env

	counter *atomic.Uint64
}

// New constructs a Resource manager and initializes all core sub-systems.
// It sets up thread-safe registries and default networking transports.
func New(opts ...Option) *Resource {
	m := &Resource{
		Metrics:    metrics.NewRegistry(),
		Health:     health.NewRegistry(),
		RouteCache: mappo.NewCache(mappo.CacheOptions{MaximumSize: woos.CacheMax, OnDelete: mappo.CloserDelete}),
		TCPCache:   mappo.NewCache(mappo.CacheOptions{MaximumSize: woos.CacheMax, OnDelete: mappo.CloserDelete}),
		AuthCache:  mappo.NewCache(mappo.CacheOptions{MaximumSize: woos.CacheMaxBig, OnDelete: mappo.CloserDelete}),
		GzCache:    mappo.NewCache(mappo.CacheOptions{MaximumSize: woos.CacheMax}),
		TimeStore:  mappo.NewConcurrent[string, time.Time](),
		counter:    new(atomic.Uint64),
		Env: &Env{
			Global: mappo.NewConcurrent[string, expect.Value](),
			Route:  mappo.NewConcurrent[string, expect.Value](),
		},
	}

	m.counter.Add(1)
	m.setDefaults()
	m.Apply(opts...)

	// register shutdown
	if m.Shutdown != nil {
		m.Shutdown.RegisterFunc("Resource", m.Close)
	}

	return m
}

// Apply executes a list of configuration options on the Resource instance.
// This is used for both initial setup and dynamic runtime re-configuration.
func (m *Resource) Apply(opts ...Option) {
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}
}

// setDefaults ensures that all required components are initialized with safe values.
// It populates the HTTP transport and background task pools if they were not provided.
func (m *Resource) setDefaults() {
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
			WriteBufferSize:       woos.BufferSize,
			ReadBufferSize:        woos.BufferSize,
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
			jack.LifetimeWithShards(woos.LifetimeShards),
		)
	}

	if m.Background == nil {
		m.Background = jack.NewPool(woos.PoolWorkers, jack.PoolingWithQueueSize(woos.PoolQueueSize))
	}

	if m.Janitor == nil {
		m.Janitor = jack.NewPool(woos.PoolWorkers, jack.PoolingWithQueueSize(woos.PoolQueueSize))
	}
}

// Validate checks the integrity of the Resource manager before it starts processing traffic.
// It returns an error if critical networking or monitoring components are uninitialized.
func (m *Resource) Validate() error {
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

// Close gracefully terminates all background processes and clears internal registries.
// It ensures that idle connections are closed and cache entries are properly disposed of.
func (m *Resource) Close() {

	if m.Janitor != nil {
		_ = m.Janitor.Shutdown(2 * time.Second)
	}

	if m.Lifetime != nil {
		m.Lifetime.Stop()
	}
	if m.Reaper != nil {
		m.Reaper.Stop()
	}
	if m.Doctor != nil {
		m.Doctor.StopAll(2 * time.Second)
	}

	m.Metrics.Clear()
	m.Health.Clear()
	m.RouteCache.Clear()
	m.TCPCache.Clear()
	m.AuthCache.Clear()
	m.GzCache.Clear()

	m.Transport.CloseIdleConnections()
}

// Counter returns the current global sequence value from the resource manager.
// This value is used for generating unique IDs across various server sub-systems.
func (m *Resource) Counter() uint64 {
	return m.counter.Load()
}

// NextID increments and returns the global counter to provide a unique identifier.
// It is used for tracking requests, tasks, and backend patient registration.
func (m *Resource) NextID() uint64 {
	return m.counter.Add(1)
}
