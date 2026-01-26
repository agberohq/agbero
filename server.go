package agbero

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"git.imaxinacion.net/aibox/agbero/internal/core/tlss"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/discovery/gossip"
	handlers2 "git.imaxinacion.net/aibox/agbero/internal/handlers"
	"git.imaxinacion.net/aibox/agbero/internal/handlers/tcp"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/firewall"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/h3"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/ratelimit"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
	"github.com/quic-go/quic-go/http3"
)

// contextKey is used to store listener port in request context
type contextKey struct {
	name string
}

var portContextKey = &contextKey{"local-port"}

type Server struct {
	hostManager *discovery.Host
	global      *alaye.Global
	tlsManager  *tlss.Manager
	configPath  string
	firewall    *firewall.IPSet

	mu         sync.RWMutex
	servers    map[string]*http.Server
	h3Servers  map[string]*http3.Server
	tcpProxies []*tcp.Proxy

	logger       *ll.Logger
	ipMiddleware *clientip.IPMiddleware
	rateLimiter  *ratelimit.RateLimiter
}

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
	s.configPath = configPath

	if s.hostManager == nil {
		return errors.New("host manager is required")
	}
	if s.global == nil {
		return errors.New("global config is required")
	}
	if s.logger == nil {
		s.logger = ll.New(woos.Name).Enable()
	}

	// Normalize config path for correct relative resolution
	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		absConfigPath = configPath
	}

	// Apply defaults (resolves HostsDir/CertsDir/DataDir relative to config)
	woos.DefaultApply(s.global, absConfigPath)

	// Log global config summary
	adminAddr := "disabled"
	if s.global.Admin != nil {
		adminAddr = s.global.Admin.Address
	}

	s.logger.Fields(
		"config_path", absConfigPath,
		"hosts_dir", s.global.Storage.HostsDir,
		"cert_dir", s.global.Storage.CertsDir,
		"data_dir", s.global.Storage.DataDir,
		"dev_mode", s.global.Development,
		"admin_addr", adminAddr,
	).Info("starting agbero")

	// Start Admin + internal subsystems
	s.startAdminServer()
	s.startCacheReaper(parentCtx)

	// Initial Host Discovery
	hosts, err := s.hostManager.LoadAll()
	if err != nil {
		s.logger.Fields("err", err).Error("failed to load initial hosts")
		return err
	}

	// Host summary + detect whether any route needs streaming-safe server timeouts
	hostCount := len(hosts)
	routeCount := 0
	tcpCount := 0
	anyStreaming := false

	for _, host := range hosts {
		routeCount += len(host.Routes)
		tcpCount += len(host.TCPProxy)

		// Scan for streaming backends: route.backend.server.streaming.enabled = true
		for _, rt := range host.Routes {
			for _, srv := range rt.Backends.Servers {
				// Assumes:
				//   srv.Streaming.Enabled bool
				// If you made Streaming a pointer, change to: if srv.Streaming != nil && srv.Streaming.Enabled { ... }
				if srv.Streaming.Enabled {
					anyStreaming = true
					break
				}
			}
			if anyStreaming {
				break
			}
		}
		if anyStreaming {
			break
		}
	}

	s.logger.Fields(
		"hosts", hostCount,
		"http_routes", routeCount,
		"tcp_routes", tcpCount,
		"streaming", anyStreaming,
	).Info("host configuration loaded")

	// Gossip Cluster Initialization
	if s.global.Gossip.Enabled {
		gs, err := gossip.NewService(s.hostManager, &s.global.Gossip, s.logger)
		if err != nil {
			return errors.Newf("failed to start gossip: %w", err)
		}
		if len(s.global.Gossip.Seeds) > 0 {
			if err := gs.Join(s.global.Gossip.Seeds); err != nil {
				s.logger.Warn("failed to join gossip seeds")
			}
		}
		defer gs.Shutdown()
	}

	// Middleware & Subsystems Initialization
	s.ipMiddleware = clientip.NewIPMiddleware(s.global.Security.TrustedProxies)
	s.rateLimiter = s.buildRateLimiterFromConfig()

	// Firewall Initialization (needs DataDir resolved)
	dataDir := woos.NewFolder(s.global.Storage.DataDir)
	s.firewall, err = firewall.New(s.global.Security.Firewall, dataDir, s.logger)
	if err != nil {
		return errors.Newf("firewall init: %w", err)
	}
	if s.firewall != nil {
		defer s.firewall.Close()
	}

	// Base handler
	baseHandler := http.HandlerFunc(s.handleRequest)

	// HTTP fallback: redirect to HTTPS if HTTPS listeners exist; otherwise serve normally
	var httpFallbackHandler http.Handler = baseHandler
	if len(s.global.Bind.HTTPS) > 0 {
		httpFallbackHandler = http.HandlerFunc(s.redirectToHTTPS)
	}

	// TLS Manager Initialization (ACME handler wrapping)
	tlsCfg, httpHandler, err := s.buildTLS(httpFallbackHandler)
	if err != nil {
		s.logger.Fields("err", err.Error()).Warn("TLS setup failed; HTTPS listeners may not start")
		// If TLS fails, do not redirect to broken HTTPS; fall back to serving app over HTTP
		httpHandler = baseHandler
		tlsCfg = nil
	}

	// Build chain: IP -> Firewall -> RateLimit -> [AltSvc] -> Router
	buildChain := func(next http.Handler, advertiseH3 bool, port string) http.Handler {
		h := next

		if advertiseH3 {
			h = h3.H3Middleware(port)(h)
		}

		if s.rateLimiter != nil {
			h = s.rateLimiter.Handler(h)
		}

		if s.firewall != nil {
			h = s.firewall.Handler(h)
		}

		if s.ipMiddleware != nil {
			h = s.ipMiddleware.Handler(h)
		}

		return h
	}

	// --- 1. Start TCP (Layer 4) Proxies ---
	for _, host := range hosts {
		for _, route := range host.TCPProxy {
			tp := tcp.NewProxy(route.Listen, s.logger)
			tp.AddRoute("*", route)

			if err := tp.Start(); err != nil {
				s.logger.Fields("listen", route.Listen, "err", err).Error("failed to start tcp proxy")
				continue
			}
			s.tcpProxies = append(s.tcpProxies, tp)
		}
	}

	// --- 2. Helper for HTTP (Layer 7) Listeners ---
	startTCPServer := func(addr string, isTLS bool) {
		_, port, _ := net.SplitHostPort(addr)

		var handler http.Handler
		if isTLS {
			handler = buildChain(baseHandler, true, port) // advertise h3 for TLS listeners
		} else {
			handler = buildChain(httpHandler, false, "")
		}

		// Inject listener port into context
		wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), portContextKey, port)
			handler.ServeHTTP(w, r.WithContext(ctx))
		})

		// IMPORTANT: if any route is streaming, server-level WriteTimeout must be 0,
		// otherwise long-lived streams get killed (e.g. VictoriaLogs /tail).
		writeTimeout := core.Or(s.global.Timeouts.Write, alaye.DefaultWriteTimeout)
		if anyStreaming {
			writeTimeout = 0
		}

		srv := &http.Server{
			Addr:              addr,
			Handler:           wrappedHandler,
			ReadTimeout:       core.Or(s.global.Timeouts.Read, alaye.DefaultReadTimeout),
			WriteTimeout:      writeTimeout,
			IdleTimeout:       core.Or(s.global.Timeouts.Idle, alaye.DefaultIdleTimeout),
			ReadHeaderTimeout: core.Or(s.global.Timeouts.ReadHeader, alaye.DefaultReadHeaderTimeout),
			MaxHeaderBytes:    s.global.General.MaxHeaderBytes,
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

	// --- 3. Helper for HTTP/3 (UDP) Listeners ---
	startQUICServer := func(addr string) {
		if tlsCfg == nil {
			return
		}
		_, port, _ := net.SplitHostPort(addr)

		handler := buildChain(baseHandler, false, "")

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
				s.logger.Fields("err", err, "proto", "h3").Error("h3 listener stopped")
			}
		}()
	}

	// --- 4. Initialize Listeners ---
	for _, addr := range s.global.Bind.HTTP {
		startTCPServer(addr, false)
	}
	for _, addr := range s.global.Bind.HTTPS {
		startTCPServer(addr, true)
		startQUICServer(addr)
	}

	if len(s.servers) == 0 && len(s.tcpProxies) == 0 {
		return errors.New("no http/https/tcp bind addresses configured")
	}

	errCh := make(chan error, len(s.servers))

	// --- 5. Start TCP Listeners ---
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

	// --- 6. Lifecycle Management ---
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range signalCh {
			switch sig {
			case syscall.SIGHUP:
				s.reload()
			case syscall.SIGINT, syscall.SIGTERM:
				cancel()
			}
		}
	}()

	return s.waitOrShutdown(ctx, errCh)
}

func (s *Server) reload() {
	s.logger.Info("received SIGHUP, reloading configuration")

	// Reload global config
	global, err := core.LoadGlobal(s.configPath)
	if err != nil {
		s.logger.Fields("err", err, "config_path", s.configPath).Error("reload config failed")
		return
	}

	var changes []string
	if s.global.Logging.Level != global.Logging.Level {
		changes = append(changes, fmt.Sprintf("log_level: %s → %s", s.global.Logging.Level, global.Logging.Level))
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

	if s.tlsManager != nil {
		s.tlsManager.ClearCache()
	}

	s.logger.Fields(
		"previous_hosts", previousCount,
		"current_hosts", currentCount,
		"change", currentCount-previousCount,
	).Info("configuration reloaded successfully")
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
			return s.shutdownImpl()
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

	// Stop TCP proxies first
	for _, tp := range s.tcpProxies {
		tp.Stop()
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Stop HTTP/3 Servers
	for key, srv := range s.h3Servers {
		if err := srv.Close(); err != nil {
			s.logger.Fields("key", key, "err", err).Warn("h3 graceful shutdown error")
		}
	}

	// Stop TCP Servers
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

	gr, gw, gb, gok := rlc.Global.Policy()
	ar, aw, ab, aok := rlc.Auth.Policy()

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

	s.tlsManager = tlss.NewManager(s.logger, s.hostManager, s.global)

	httpHandler, err := s.tlsManager.EnsureCertMagic(next)
	if err != nil {
		s.logger.Fields("err", err.Error()).Warn("certmagic not enabled; using HTTP handler without ACME")
		httpHandler = next
	}

	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{"h3", "h2", "http/1.1"},
		GetCertificate: s.tlsManager.GetCertificate,
	}

	return tlsCfg, httpHandler, nil
}

func (s *Server) logRequest(host string, r *http.Request, start time.Time, status int, bytes int64) {
	if s.logger == nil {
		return
	}

	fields := []interface{}{
		"host", host,
		"path", r.URL.Path,
		"remote", clientip.ClientIP(r),
		"duration", time.Since(start),
		"proto", r.Proto,
		"status", status,
		"bytes", bytes,
	}

	if port, ok := r.Context().Value(portContextKey).(string); ok && port != "" {
		fields = append(fields, "port", port)
	}

	if s.global != nil && s.shouldLogUserAgent(r) {
		fields = append(fields, "ua", truncateUA(r.UserAgent(), 50))
	}

	s.logger.Fields(fields...).Info(r.Method)
}

func (s *Server) shouldLogUserAgent(r *http.Request) bool {
	ua := r.UserAgent()
	return strings.Contains(ua, "bot") ||
		strings.Contains(ua, "crawl") ||
		strings.Contains(ua, "spider") ||
		len(ua) > 100
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := core.NormalizeHost(r.Host)

	hcfg := s.hostManager.Get(host)
	if hcfg == nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		s.logRequest(host, r, start, http.StatusNotFound, 0)
		return
	}

	if len(hcfg.BindPorts) > 0 {
		portCtx := r.Context().Value(portContextKey)
		listenerPort, ok := portCtx.(string)

		if ok && listenerPort != "" {
			allowed := false
			for _, p := range hcfg.BindPorts {
				if p == listenerPort {
					allowed = true
					break
				}
			}
			if !allowed {
				http.Error(w, "Misdirected Request", http.StatusMisdirectedRequest)
				s.logRequest(host, r, start, http.StatusMisdirectedRequest, 0)
				return
			}
		}
	}

	maxBody := int64(alaye.DefaultMaxBodySize)
	if &hcfg.Limits != nil && hcfg.Limits.MaxBodySize > 0 {
		maxBody = hcfg.Limits.MaxBodySize
	}

	if r.ContentLength > maxBody {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		s.logRequest(host, r, start, http.StatusRequestEntityTooLarge, 0)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	router := s.hostManager.GetRouter(host)
	if router == nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		s.logRequest(host, r, start, http.StatusNotFound, 0)
		return
	}

	res := router.Find(r.URL.Path)
	if res.Route != nil {
		rw := &responseWrapper{ResponseWriter: w, statusCode: 200}
		s.handleRoute(rw, r, res.Route)
		s.logRequest(host, r, start, rw.statusCode, rw.bytesWritten)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
	s.logRequest(host, r, start, http.StatusNotFound, 0)
}

func (s *Server) handleRoute(w http.ResponseWriter, r *http.Request, route *alaye.Route) {
	// Safe Request Copy logic
	reqOut := *r
	if r.URL != nil {
		u := *r.URL
		reqOut.URL = &u
	}

	if len(route.StripPrefixes) > 0 {
		for _, prefix := range route.StripPrefixes {
			if prefix == "" {
				continue
			}
			if strings.HasPrefix(reqOut.URL.Path, prefix) {
				reqOut.URL.Path = strings.TrimPrefix(reqOut.URL.Path, prefix)
				if reqOut.URL.RawPath != "" {
					reqOut.URL.RawPath = strings.TrimPrefix(reqOut.URL.RawPath, prefix)
				}
				if reqOut.URL.Path == "" {
					reqOut.URL.Path = "/"
				}
				break
			}
		}
	}

	h := s.getOrBuildRouteHandler(route)
	h.ServeHTTP(w, &reqOut)
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

func (s *Server) redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	// 1. Get the host without the incoming HTTP port
	// e.g. "example.com:8080" -> "example.com"
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		// If there is no port in the Host header, use it as is
		host = r.Host
	}

	// 2. Determine the target HTTPS port from global config
	targetPort := "443" // Default
	if len(s.global.Bind.HTTPS) > 0 {
		// We use the first configured HTTPS address as the redirect target
		_, port, err := net.SplitHostPort(s.global.Bind.HTTPS[0])
		if err == nil {
			targetPort = port
		}
	}

	// 3. Construct the destination URL
	var target string
	if targetPort == "443" {
		// Standard HTTPS (clean URL)
		target = fmt.Sprintf("https://%s%s", host, r.URL.RequestURI())
	} else {
		// Non-standard port (e.g. https://example.com:8443/foo)
		target = fmt.Sprintf("https://%s:%s%s", host, targetPort, r.URL.RequestURI())
	}

	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func truncateUA(ua string, maxLen int) string {
	if len(ua) <= maxLen {
		return ua
	}
	return ua[:maxLen] + "..."
}

type responseWrapper struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
	wroteHeader  bool
}

func (rw *responseWrapper) WriteHeader(statusCode int) {
	if !rw.wroteHeader {
		rw.statusCode = statusCode
		rw.wroteHeader = true
	}
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWrapper) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}

func (rw *responseWrapper) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
