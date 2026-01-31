package agbero

import (
	"context"
	"crypto/tls"
	"encoding/json"
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
	"git.imaxinacion.net/aibox/agbero/internal/middleware/wasm"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
	"github.com/quic-go/quic-go/http3"
)

type contextKey struct {
	name string
}

var portContextKey = &contextKey{woos.CtxPort}

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

	wasmCache sync.Map
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
		return woos.ErrHostManagerRequired
	}
	if s.global == nil {
		return woos.ErrGlobalConfigRequired
	}
	if s.logger == nil {
		s.logger = ll.New(woos.Name).Enable()
	}

	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		absConfigPath = configPath
	}

	woos.DefaultApply(s.global, absConfigPath)

	adminAddr := woos.DefaultConfigAddr
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

	s.startAdminServer()
	s.startCacheReaper(parentCtx)

	hosts, err := s.hostManager.LoadAll()
	if err != nil {
		s.logger.Fields("err", err).Error("failed to load initial hosts")
		return err
	}

	hostCount := len(hosts)
	routeCount := 0
	tcpCount := 0
	anyStreaming := false

	for _, host := range hosts {
		routeCount += len(host.Routes)
		tcpCount += len(host.TCPProxy)

		for _, rt := range host.Routes {
			for _, srv := range rt.Backends.Servers {
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

	s.ipMiddleware = clientip.NewIPMiddleware(s.global.Security.TrustedProxies)
	s.rateLimiter = s.buildRateLimiterFromConfig()

	dataDir := woos.NewFolder(s.global.Storage.DataDir)
	s.firewall, err = firewall.New(s.global.Security.Firewall, dataDir, s.logger)
	if err != nil {
		return errors.Newf("firewall init: %w", err)
	}
	if s.firewall != nil {
		defer s.firewall.Close()
	}

	baseHandler := http.HandlerFunc(s.handleRequest)

	var httpFallbackHandler http.Handler = baseHandler
	if len(s.global.Bind.HTTPS) > 0 {
		httpFallbackHandler = http.HandlerFunc(s.redirectToHTTPS)
	}

	tlsCfg, _, err := s.buildTLS(httpFallbackHandler)
	if err != nil {
		s.logger.Fields("err", err.Error()).Warn("TLS setup failed; HTTPS listeners may not start")
		tlsCfg = nil
	}

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

	usedPorts := make(map[string]bool)

	for _, addr := range s.global.Bind.HTTP {
		_, port, _ := net.SplitHostPort(addr)
		usedPorts[port] = true
		s.startTCPServer(addr, false, nil, nil, baseHandler, httpFallbackHandler, anyStreaming)
	}

	for _, addr := range s.global.Bind.HTTPS {
		_, port, _ := net.SplitHostPort(addr)
		usedPorts[port] = true
		s.startTCPServer(addr, true, nil, tlsCfg, baseHandler, httpFallbackHandler, anyStreaming)
		s.startQUICServer(addr, nil, tlsCfg, baseHandler)
	}

	for _, h := range hosts {
		for _, port := range h.Bind {
			if usedPorts[port] {
				return errors.Newf("%w: %s is already in use by a global listener or another host", woos.ErrPortConflict, port)
			}
			usedPorts[port] = true

			addr := ":" + port
			// Determine if private binding should use TLS
			isTLS := true
			if h.TLS.Mode == alaye.ModeLocalNone {
				isTLS = false
			}

			s.startTCPServer(addr, isTLS, h, tlsCfg, baseHandler, httpFallbackHandler, anyStreaming)
			// Only start QUIC if TLS is enabled
			if isTLS {
				s.startQUICServer(addr, h, tlsCfg, baseHandler)
			}
		}
	}

	if len(s.servers) == 0 && len(s.tcpProxies) == 0 {
		return woos.ErrNoBindAddr
	}

	errCh := make(chan error, len(s.servers))

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

func (s *Server) startTCPServer(
	addr string,
	isTLS bool,
	owner *alaye.Host,
	tlsCfg *tls.Config,
	baseHandler http.Handler,
	httpHandler http.Handler,
	anyStreaming bool,
) {
	_, port, _ := net.SplitHostPort(addr)

	var handler http.Handler
	if isTLS {
		handler = s.buildChain(baseHandler, true, port)
	} else {
		handler = s.buildChain(httpHandler, false, "")
	}

	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, portContextKey, port)
		if owner != nil {
			ctx = context.WithValue(ctx, woos.OwnerKey, owner)
		}
		handler.ServeHTTP(w, r.WithContext(ctx))
	})

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
		if owner != nil {
			localCfg := tlsCfg.Clone()
			localCfg.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				cert, err := s.tlsManager.GetCertificate(chi)
				if err == nil {
					return cert, nil
				}
				if len(owner.Domains) > 0 {
					chi.ServerName = owner.Domains[0]
					return s.tlsManager.GetCertificate(chi)
				}
				return nil, err
			}
			srv.TLSConfig = localCfg
		} else {
			srv.TLSConfig = tlsCfg
		}
	}

	key := core.ServerKey(addr, isTLS)
	s.mu.Lock()
	s.servers[key] = srv
	s.mu.Unlock()
}

func (s *Server) startQUICServer(
	addr string,
	owner *alaye.Host,
	tlsCfg *tls.Config,
	baseHandler http.Handler,
) {
	if tlsCfg == nil {
		return
	}
	_, port, _ := net.SplitHostPort(addr)

	handler := s.buildChain(baseHandler, false, "")

	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, portContextKey, port)
		if owner != nil {
			ctx = context.WithValue(ctx, woos.OwnerKey, owner)
		}
		handler.ServeHTTP(w, r.WithContext(ctx))
	})

	serverTLSCfg := tlsCfg
	if owner != nil {
		localCfg := tlsCfg.Clone()
		localCfg.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := s.tlsManager.GetCertificate(chi)
			if err == nil {
				return cert, nil
			}
			if len(owner.Domains) > 0 {
				chi.ServerName = owner.Domains[0]
				return s.tlsManager.GetCertificate(chi)
			}
			return nil, err
		}
		serverTLSCfg = localCfg
	}

	h3Server := &http3.Server{
		Addr:      addr,
		Handler:   wrappedHandler,
		TLSConfig: serverTLSCfg,
	}

	key := woos.H3KeyPrefix + addr
	s.mu.Lock()
	s.h3Servers[key] = h3Server
	s.mu.Unlock()

	go func() {
		s.logger.Fields("bind", addr, "proto", "h3").Info("listener starting")
		if err := h3Server.ListenAndServe(); err != nil {
			s.logger.Fields("err", err, "proto", "h3").Warn("h3 listener stopped")
		}
	}()
}

func (s *Server) buildChain(next http.Handler, advertiseH3 bool, port string) http.Handler {
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

func (s *Server) reload() {
	s.logger.Info("received SIGHUP, reloading configuration")

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

	for _, tp := range s.tcpProxies {
		tp.Stop()
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for key, srv := range s.h3Servers {
		if err := srv.Close(); err != nil {
			s.logger.Fields("key", key, "err", err).Warn("h3 graceful shutdown error")
		}
	}

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
	//expiration := woos.RouteCacheTTL

	woos.RouteCache.Range(func(key, value any) bool {
		item, ok := value.(*woos.RouteCacheItem)
		if !ok {
			return true
		}

		last := item.LastAccessed.Load()
		if now-last > woos.RouteCacheTTL {
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

	ttl := core.Or(rlc.TTL, woos.DefaultRateLimitTTL)
	maxEntries := rlc.MaxEntries
	if maxEntries <= 0 {
		maxEntries = woos.DefaultRateLimitMaxEntries
	}

	gr, gw, gb, gok := rlc.Global.Policy()
	ar, aw, ab, aok := rlc.Auth.Policy()

	globalPolicy := ratelimit.RatePolicy{Requests: gr, Window: gw, Burst: gb, KeyHeader: rlc.Global.KeyHeader}
	authPolicy := ratelimit.RatePolicy{Requests: ar, Window: aw, Burst: ab, KeyHeader: rlc.Global.KeyHeader}

	authPrefixes := rlc.AuthPrefixes
	if len(authPrefixes) == 0 {
		authPrefixes = []string{"/login", "/otp", "/auth"}
	}

	policy := func(r *http.Request) (bucket string, pol ratelimit.RatePolicy, ok bool) {
		p := r.URL.Path

		if strings.HasPrefix(p, "/.well-known/acme-challenge/") {
			return woos.BucketACME, ratelimit.RatePolicy{}, false
		}

		for _, pref := range authPrefixes {
			if pref != "" && strings.HasPrefix(p, pref) {
				if aok {
					return woos.BucketAuth, authPolicy, true
				}
				return woos.BucketAuthDisabled, ratelimit.RatePolicy{}, false
			}
		}

		if gok {
			return woos.BucketGlobal, globalPolicy, true
		}
		return woos.BucketGlobalDisabled, ratelimit.RatePolicy{}, false
	}

	return ratelimit.NewRateLimiter(ttl, maxEntries, policy)
}

func (s *Server) buildTLS(next http.Handler) (*tls.Config, http.Handler, error) {
	if s.global == nil {
		return nil, nil, woos.ErrGlobalConfigRequired
	}
	if s.logger == nil {
		return nil, nil, woos.ErrLoggerRequired
	}
	if s.hostManager == nil {
		return nil, nil, woos.ErrHostManagerRequired
	}

	s.tlsManager = tlss.NewManager(s.logger, s.hostManager, s.global)

	httpHandler, err := s.tlsManager.EnsureCertMagic(next)
	if err != nil {
		s.logger.Fields("err", err.Error()).Warn("certmagic not enabled; using HTTP handler without ACME")
		httpHandler = next
	}

	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		NextProtos:     []string{woos.AlpnH3, woos.AlpnH2, woos.AlpnH11},
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
	var host string
	var hcfg *alaye.Host

	// 1. Check Port Ownership (Short-Circuit)
	if owner, ok := r.Context().Value(woos.OwnerKey).(*alaye.Host); ok && owner != nil {
		hcfg = owner
		if len(hcfg.Domains) > 0 {
			host = hcfg.Domains[0]
		} else {
			host = woos.PrivateBindingHost
		}
	} else {
		// 2. Standard Global Listener (SNI/Hosting based)
		host = core.NormalizeHost(r.Host)
		hcfg = s.hostManager.Get(host)
	}

	if hcfg == nil {
		http.Error(w, "Hosting not found", http.StatusNotFound)
		s.logRequest(host, r, start, http.StatusNotFound, 0)
		return
	}

	// NOTE: Misdirected Request check has been removed to allow
	// requests on global listeners even if private bind ports are configured.

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

	var routerName string
	if len(hcfg.Domains) > 0 {
		routerName = hcfg.Domains[0]
	} else {
		routerName = host
	}

	router := s.hostManager.GetRouter(routerName)
	if router == nil && routerName != host {
		router = s.hostManager.GetRouter(host)
	}

	if router == nil {
		http.Error(w, "Hosting configuration found but router unavailable", http.StatusNotFound)
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
	// Clone request to ensure thread safety when modifying path/URL
	reqOut := *r
	if r.URL != nil {
		u := *r.URL
		reqOut.URL = &u
	}

	// 1. Strip Prefixes logic
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

	// 2. Get the core handler (Reverse Proxy or File Server)
	// This is cached by the Route Key in the global RouteCache
	var handler http.Handler = s.getOrBuildRouteHandler(route)

	// 3. Apply WASM Middleware (if configured)
	if route.Wasm != nil {
		wm, err := s.getWasmManager(route.Wasm)
		if err != nil {
			s.logger.Fields("err", err, "module", route.Wasm.Module).Error("wasm: failed to load middleware")
			// Fail open or closed? Usually closed for middleware errors.
			http.Error(w, "Internal Server Error (WASM)", http.StatusInternalServerError)
			return
		}
		// Wrap the core handler with the WASM handler
		handler = wm.Handler(handler)
	}

	// 4. Execute
	handler.ServeHTTP(w, &reqOut)
}

func (s *Server) getOrBuildRouteHandler(route *alaye.Route) *handlers2.Route {
	key := route.Key()
	now := time.Now().UnixNano()

	if v, ok := woos.RouteCache.Load(key); ok {
		item := v.(*woos.RouteCacheItem)
		item.LastAccessed.Store(now)
		return item.Handler.(*handlers2.Route)
	}

	h := handlers2.NewRoute(route, s.logger)
	newItem := &woos.RouteCacheItem{
		Handler: h,
	}
	newItem.LastAccessed.Store(now)

	if v, loaded := woos.RouteCache.LoadOrStore(key, newItem); loaded {
		h.Close()
		item := v.(*woos.RouteCacheItem)
		item.LastAccessed.Store(now)
		return item.Handler.(*handlers2.Route)
	}

	return h
}

func (s *Server) getWasmManager(cfg *alaye.Wasm) (*wasm.Manager, error) {
	// Create a unique cache key based on the module path AND the configuration map.
	// We use JSON marshalling to create a deterministic string key.
	// This ensures that if the config block changes, we get a new instance.
	keyBytes, _ := json.Marshal(cfg)
	key := string(keyBytes)

	// Fast path: Load from cache
	if v, ok := s.wasmCache.Load(key); ok {
		return v.(*wasm.Manager), nil
	}

	// Slow path: Compile and Initialize
	// Using Background context here because the Manager lifecycle lives beyond the request
	mgr, err := wasm.NewManager(context.Background(), s.logger, cfg)
	if err != nil {
		return nil, err
	}

	// Store in cache
	// Use LoadOrStore to handle race conditions during startup
	if actual, loaded := s.wasmCache.LoadOrStore(key, mgr); loaded {
		// Another goroutine beat us, close our unused one and use theirs
		mgr.Close(context.Background())
		return actual.(*wasm.Manager), nil
	}

	return mgr, nil
}

func (s *Server) redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	targetPort := woos.DefaultHTTPSPortInt
	if len(s.global.Bind.HTTPS) > 0 {
		_, port, err := net.SplitHostPort(s.global.Bind.HTTPS[0])
		if err == nil {
			targetPort = port
		}
	}

	var target string
	if targetPort == woos.DefaultHTTPSPortInt {
		target = fmt.Sprintf("https://%s%s", host, r.URL.RequestURI())
	} else {
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
