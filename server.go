// server.go
package agbero

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"git.imaxinacion.net/aibox/agbero/internal/core/tlss"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/discovery/gossip"
	handlers2 "git.imaxinacion.net/aibox/agbero/internal/handlers"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/h3"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/ratelimit"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
	"github.com/quic-go/quic-go/http3"
)

type Server struct {
	hostManager *discovery.Host
	global      *alaye.Global
	tlsManager  *tlss.Manager // Added for watcher shutdown
	configPath  string        // Added for reload

	mu sync.RWMutex
	// TCP Servers (HTTP/1.1 & HTTP/2)
	servers map[string]*http.Server
	// UDP Servers (HTTP/3 QUIC)
	h3Servers map[string]*http3.Server

	logger       *ll.Logger
	ipMiddleware *clientip.IPMiddleware
	rateLimiter  *ratelimit.RateLimiter
}

// contextKey is used to store listener port in request context
type contextKey struct {
	name string
}

var portContextKey = &contextKey{"local-port"}

func NewServer(opts ...Option) *Server {
	s := &Server{
		servers:   make(map[string]*http.Server),
		h3Servers: make(map[string]*http3.Server),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Server) Start(parentCtx context.Context, configPath string) error {
	s.configPath = configPath // Set for reload

	if s.hostManager == nil {
		return errors.New("host manager is required")
	}
	if s.global == nil {
		return errors.New("global config is required")
	}
	if s.logger == nil {
		s.logger = ll.New(woos.Name).Enable()
	}

	woos.ApplyDefaults(s.global)

	// Log global config summary
	s.logger.Fields(
		"config_path", configPath,
		"hosts_dir", s.global.HostsDir,
		"dev_mode", s.global.Development,
		"http_bind", len(s.global.Bind.HTTP),
		"https_bind", len(s.global.Bind.HTTPS),
		"metrics_bind", s.global.Bind.Metrics,
	).Info("starting with configuration")

	s.startMetricsServer()
	s.startCacheReaper(parentCtx)

	// Log initial host discovery
	hosts, err := s.hostManager.LoadAll()
	if err != nil {
		s.logger.Fields("err", err).Error("failed to load initial hosts")
		return err
	}

	// Log host summary
	hostCount := len(hosts)
	routeCount := 0
	domainCount := 0
	for domain, host := range hosts {
		domainCount++
		routeCount += len(host.Routes)

		s.logger.Fields(
			"domain", domain,
			"routes", len(host.Routes),
			"tls_mode", host.TLS,
		).Debug("host configuration loaded")
	}

	s.logger.Fields(
		"hosts", hostCount,
		"domains", domainCount,
		"routes", routeCount,
	).Info("host configuration loaded successfully")

	if &s.global.Gossip != nil && s.global.Gossip.Enabled {
		gs, err := gossip.NewService(s.hostManager, &s.global.Gossip, s.logger)
		if err != nil {
			return errors.Newf("failed to start gossip: %w", err)
		}
		// Join known seeds if any (e.g., other Agbero nodes for HA)
		if len(s.global.Gossip.Seeds) > 0 {
			if err := gs.Join(s.global.Gossip.Seeds); err != nil {
				s.logger.Warn("failed to join gossip seeds")
			}
		}

		// Ensure shutdown
		defer gs.Shutdown()
	}

	s.ipMiddleware = clientip.NewIPMiddleware(s.global.TrustedProxies)
	s.rateLimiter = s.buildRateLimiterFromConfig()

	baseHandler := http.HandlerFunc(s.handleRequest)

	tlsCfg, httpHandler, err := s.buildTLS(baseHandler)
	if err != nil {
		s.logger.Fields("err", err.Error()).Warn("TLS setup failed; HTTPS listeners may not start")
		httpHandler = baseHandler
		tlsCfg = nil
	}

	// Helper to spawn standard TCP servers (HTTP/HTTPS)
	startTCPServer := func(addr string, isTLS bool) {
		var handler http.Handler

		if isTLS {
			// For TLS, we add the H3Middleware to advertise QUIC support via Alt-Svc header
			port := h3.ExtractPort(addr)
			advertiseH3 := h3.H3Middleware(port)

			// Chain: IP -> Rate -> Alt-Svc -> (HTTP-01) -> Router
			handler = s.ipMiddleware.Handler(s.rateLimiter.Handler(advertiseH3(baseHandler)))
		} else {
			handler = s.ipMiddleware.Handler(s.rateLimiter.Handler(httpHandler))
		}

		// Inject Port into Context
		_, port, _ := net.SplitHostPort(addr)
		wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), portContextKey, port)
			handler.ServeHTTP(w, r.WithContext(ctx))
		})

		srv := &http.Server{
			Addr:              addr,
			Handler:           wrappedHandler,
			ReadTimeout:       core.Or(s.global.Timeouts.Read, alaye.DefaultReadTimeout),
			WriteTimeout:      core.Or(s.global.Timeouts.Write, alaye.DefaultWriteTimeout),
			IdleTimeout:       core.Or(s.global.Timeouts.Idle, alaye.DefaultIdleTimeout),
			ReadHeaderTimeout: core.Or(s.global.Timeouts.ReadHeader, alaye.DefaultReadHeaderTimeout),
			MaxHeaderBytes:    s.global.MaxHeaderBytes,
		}

		if srv.MaxHeaderBytes == 0 {
			srv.MaxHeaderBytes = alaye.DefaultMaxHeaderBytes
		}

		if isTLS && tlsCfg != nil {
			srv.TLSConfig = tlsCfg
		}

		key := core.ServerKey(addr, isTLS)
		s.mu.Lock()
		s.servers[key] = srv
		s.mu.Unlock()
	}

	// Helper to spawn UDP servers (HTTP/3)
	startQUICServer := func(addr string) {
		if tlsCfg == nil {
			return
		}

		// Reuse logic: IP -> Rate -> Router
		// Note: HTTP/3 doesn't need Alt-Svc middleware because we are already ON HTTP/3
		handler := s.ipMiddleware.Handler(s.rateLimiter.Handler(baseHandler))

		// Inject Port Context
		_, port, _ := net.SplitHostPort(addr)
		wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), portContextKey, port)
			handler.ServeHTTP(w, r.WithContext(ctx))
		})

		h3Server := &http3.Server{
			Addr:      addr,
			Handler:   wrappedHandler,
			TLSConfig: tlsCfg,
		}

		key := "h3@" + addr
		s.mu.Lock()
		s.h3Servers[key] = h3Server
		s.mu.Unlock()

		go func() {
			s.logger.Fields("bind", addr, "proto", "h3").Info("listener starting")
			if err := h3Server.ListenAndServe(); err != nil {
				// quic-go doesn't have a specific "ErrServerClosed" for graceful Shutdown yet in all versions,
				// but usually returns nil or a specific error on Close.
				s.logger.Fields("err", err, "proto", "h3").Error("h3 listener stopped")
			}
		}()
	}

	// 1. Initialize HTTP (TCP)
	for _, addr := range s.global.Bind.HTTP {
		startTCPServer(addr, false)
	}

	// 2. Initialize HTTPS (TCP) + HTTP/3 (UDP)
	for _, addr := range s.global.Bind.HTTPS {
		startTCPServer(addr, true)
		startQUICServer(addr)
	}

	if len(s.servers) == 0 {
		return errors.New("no http or https bind addresses configured")
	}

	errCh := make(chan error, len(s.servers))

	// 3. Start TCP Listeners
	s.mu.RLock()
	for key, srv := range s.servers {
		key := key
		srv := srv

		go func() {
			s.logger.Fields("bind", srv.Addr, "key", key).Info("listener starting")

			var err error
			if core.IsServerKeyTLS(key) {
				err = srv.ListenAndServeTLS("", "")
			} else {
				err = srv.ListenAndServe()
			}

			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
				return
			}
			errCh <- nil
		}()
	}
	s.mu.RUnlock()

	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	// Handle signals for reload/shutdown
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range signalCh {
			switch sig {
			case syscall.SIGHUP:
				s.reload()
			case syscall.SIGINT, syscall.SIGTERM:
				cancel() // Now valid due to Fix B
			}
		}
	}()

	return s.waitOrShutdown(ctx, errCh)
}

// reload reloads config and hosts
// server.go - Update reload method
func (s *Server) reload() {
	s.logger.Info("received SIGHUP, reloading configuration")

	// Reload global config
	global, err := core.LoadGlobal(s.configPath)
	if err != nil {
		s.logger.Fields("err", err, "config_path", s.configPath).Error("reload config failed")
		return
	}

	// Log changes in global config
	var changes []string
	if s.global.LEEmail != global.LEEmail {
		changes = append(changes, fmt.Sprintf("le_email: %s → %s", s.global.LEEmail, global.LEEmail))
	}

	if s.global.Logging.Level != global.Logging.Level {
		changes = append(changes, fmt.Sprintf("log_level: %s → %s", s.global.Logging.Level, global.Logging.Level))
		// s.logger.Level(global.Logging.Level)
	}

	s.global = global

	if len(changes) > 0 {
		s.logger.Fields("changes", changes).Info("global config updated")
	}

	// Reload hosts
	previousHosts, _ := s.hostManager.LoadAll()
	previousCount := len(previousHosts)

	s.hostManager.ReloadFull()

	currentHosts, _ := s.hostManager.LoadAll()
	currentCount := len(currentHosts)

	s.logger.Fields(
		"previous_hosts", previousCount,
		"current_hosts", currentCount,
		"change", currentCount-previousCount,
	).Info("configuration reloaded successfully")
}

func (s *Server) startMetricsServer() {
	if s.global.Bind.Metrics == "" {
		return
	}

	mux := http.NewServeMux()

	// The core metrics endpoint (JSON structure with HdrHistogram stats)
	mux.HandleFunc("/metrics", handlers2.MetricsHandler(s.hostManager))

	// Simple liveness probe for load balancers (AWS ALB, K8s, etc.)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	srv := &http.Server{
		Addr:         s.global.Bind.Metrics,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		s.logger.Fields("bind", s.global.Bind.Metrics).Info("metrics listener starting")

		// We ignore ErrServerClosed because it occurs during normal Shutdown
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Fields("err", err).Error("metrics server failed")
		}
	}()
}

func (s *Server) startCacheReaper(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.reapOldRoutes()
			}
		}
	}()
}

func (s *Server) waitOrShutdown(ctx context.Context, errCh <-chan error) error {
	for {
		select {
		case <-ctx.Done():
			return s.shutdownImpl() // Separated for clarity
		case err := <-errCh:
			if err != nil {
				_ = s.shutdownImpl()
				return err
			}
		}
	}
}

func (s *Server) shutdownImpl() error {
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// 1. Stop HTTP/3 Servers gracefully
	for key, srv := range s.h3Servers {
		if err := srv.Close(); err != nil {
			s.logger.Fields("key", key, "err", err).Warn("h3 graceful shutdown error")
		}
	}

	// 2. Stop TCP Servers
	var firstErr error
	for key, srv := range s.servers {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := srv.Shutdown(ctx)
		cancel()

		if err != nil && firstErr == nil {
			firstErr = err
		}
		s.logger.Fields("key", key).Info("listener stopped")
	}

	// Close TLS manager watchers
	if s.tlsManager != nil {
		s.tlsManager.Close()
	}

	return firstErr
}

func (s *Server) reapOldRoutes() {
	now := time.Now().UnixNano()
	expiration := int64(10 * time.Minute)

	woos.RouteCache.Range(func(key, value any) bool {
		item, ok := value.(*woos.RouteCacheItem)
		if !ok {
			return true
		}

		last := item.LastAccessed.Load()
		if now-last > expiration {
			if h, ok := item.Handler.(interface{ Close() }); ok {
				h.Close()
			}
			woos.RouteCache.Delete(key)
		}
		return true
	})
}

func (s *Server) buildRateLimiterFromConfig() *ratelimit.RateLimiter {
	rlc := s.global.RateLimits

	ttl := core.Or(rlc.TTL, 30*time.Minute)
	maxEntries := rlc.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 100_000
	}

	gr, gw, gb, gok := woos.ParseRatePolicy(rlc.Global)
	ar, aw, ab, aok := woos.ParseRatePolicy(rlc.Auth)

	globalPolicy := ratelimit.RatePolicy{Requests: gr, Window: gw, Burst: gb}
	authPolicy := ratelimit.RatePolicy{Requests: ar, Window: aw, Burst: ab}

	authPrefixes := rlc.AuthPrefixes
	if len(authPrefixes) == 0 {
		authPrefixes = []string{"/login", "/otp", "/auth"}
	}

	policy := func(r *http.Request) (bucket string, pol ratelimit.RatePolicy, ok bool) {
		p := r.URL.Path

		if strings.HasPrefix(p, "/.well-known/acme-challenge/") {
			return "acme", ratelimit.RatePolicy{}, false
		}

		for _, pref := range authPrefixes {
			if pref != "" && strings.HasPrefix(p, pref) {
				if aok {
					return "auth", authPolicy, true
				}
				return "auth_disabled", ratelimit.RatePolicy{}, false
			}
		}

		if gok {
			return "global", globalPolicy, true
		}
		return "global_disabled", ratelimit.RatePolicy{}, false
	}

	return ratelimit.NewRateLimiter(ttl, maxEntries, policy)
}

func (s *Server) logRequest(host string, r *http.Request, start time.Time) {
	s.logger.Fields(
		"host", host,
		"method", r.Method,
		"path", r.URL.Path,
		"remote", clientip.ClientIP(r),
		"ua", r.UserAgent(),
		"duration", time.Since(start),
		"proto", r.Proto, // Useful to see "HTTP/3.0"
	).Info("request")
}

func (s *Server) getOrBuildRouteHandler(route *alaye.Route) *handlers2.RouteHandler {
	key := route.Key()
	now := time.Now().UnixNano()

	if v, ok := woos.RouteCache.Load(key); ok {
		item := v.(*woos.RouteCacheItem)
		item.LastAccessed.Store(now) // Touch
		return item.Handler.(*handlers2.RouteHandler)
	}

	h := handlers2.NewRouteHandler(route, s.logger)
	newItem := &woos.RouteCacheItem{
		Handler: h,
	}
	newItem.LastAccessed.Store(now)

	if v, loaded := woos.RouteCache.LoadOrStore(key, newItem); loaded {
		h.Close()
		item := v.(*woos.RouteCacheItem)
		item.LastAccessed.Store(now)
		return item.Handler.(*handlers2.RouteHandler)
	}

	return h
}

func (s *Server) buildTLS(next http.Handler) (*tls.Config, http.Handler, error) {
	if s.global == nil {
		return nil, nil, errors.New("global config is required")
	}
	if s.logger == nil {
		return nil, nil, errors.New("logger is required")
	}
	if s.hostManager == nil {
		return nil, nil, errors.New("host manager is required")
	}

	s.tlsManager = tlss.NewManager(s.logger, s.hostManager, s.global) // Set on Server

	httpHandler, err := s.tlsManager.EnsureCertMagic(next)
	if err != nil {
		s.logger.Fields("err", err.Error()).Warn("certmagic not enabled; using HTTP handler without ACME")
		httpHandler = next
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// http3 requires "h3" in ALPN
		NextProtos:     []string{"h3", "h2", "http/1.1"},
		GetCertificate: s.tlsManager.GetCertificate,
	}

	return tlsCfg, httpHandler, nil
}
