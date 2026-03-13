package resource

import (
	"net"
	"net/http"
	"time"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/agberohq/agbero/internal/pkg/metrics"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/mappo"
)

type Manager struct {
	Metrics    *metrics.Registry
	Health     *health.Registry
	RouteCache *mappo.Cache
	TCPCache   *mappo.Cache
	AuthCache  *mappo.Cache
	GzCache    *mappo.Cache

	Transport  *http.Transport
	HTTPClient *http.Client
}

func New() *Manager {
	t := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   woos.DefaultTransportDialTimeout,
			KeepAlive: woos.DefaultTransportKeepAlive,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10000,
		MaxIdleConnsPerHost:   10000,
		IdleConnTimeout:       woos.DefaultTransportIdleConnTimeout,
		TLSHandshakeTimeout:   woos.DefaultTransportTLSHandshakeTimeout,
		ResponseHeaderTimeout: woos.DefaultTransportResponseHeaderTimeout,
		ExpectContinueTimeout: 0,
	}

	return &Manager{
		Metrics:    metrics.NewRegistry(),
		Health:     health.NewRegistry(),
		RouteCache: mappo.NewCache(mappo.CacheOptions{MaximumSize: woos.CacheMax, OnDelete: mappo.CloserDelete}),
		TCPCache:   mappo.NewCache(mappo.CacheOptions{MaximumSize: woos.CacheMax, OnDelete: mappo.CloserDelete}),
		AuthCache:  mappo.NewCache(mappo.CacheOptions{MaximumSize: 100_000, OnDelete: mappo.CloserDelete}),
		GzCache:    mappo.NewCache(mappo.CacheOptions{MaximumSize: woos.CacheMax}),
		Transport:  t,
		HTTPClient: &http.Client{
			Timeout:   5 * time.Second,
			Transport: t,
		},
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
}
