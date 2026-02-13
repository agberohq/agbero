package agbero

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"git.imaxinacion.net/aibox/agbero/internal/core/cache"
	"git.imaxinacion.net/aibox/agbero/internal/core/tlss"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/discovery/gossip"
	"git.imaxinacion.net/aibox/agbero/internal/handlers"
	"git.imaxinacion.net/aibox/agbero/internal/handlers/tcp"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/firewall"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/h3"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/metrics"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/ratelimit"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/recovery"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/wasm"
	"git.imaxinacion.net/aibox/agbero/internal/ui"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/quic-go/quic-go/http3"
)

var portContextKey = &contextKey{woos.CtxPort}

type contextKey struct {
	name string
}

type Server struct {
	configPath string
	configSHA  string

	hostManager *discovery.Host
	global      *alaye.Global
	tlsManager  *tlss.Manager
	firewall    *firewall.IPSet

	mu         sync.RWMutex
	servers    map[string]*http.Server
	h3Servers  map[string]*http3.Server
	tcpProxies []*tcp.Proxy

	logger       *ll.Logger
	ipMiddleware *clientip.IPMiddleware
	rateLimiter  *ratelimit.RateLimiter

	wasmCache    sync.Map
	skipLogPaths map[string]bool

	shutdown *jack.Shutdown
	reaper   *jack.Reaper

	ProxyProtocol  bool  `hcl:"proxy_protocol,optional" json:"proxy_protocol"`
	MaxConnections int64 `hcl:"max_connections,optional" json:"max_connections"`

	h3Wg sync.WaitGroup
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

func (s *Server) Start(configPath string) error {
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

	sha, err := s.computeFullConfigSHA()
	if err != nil {
		s.logger.Warn("could not compute config sha: ", err)
	} else {
		s.configSHA = sha
		s.logger.Fields(
			"config_path", absConfigPath,
			"sha256", sha[:12],
		).Infof("config loaded")
	}
	s.logger.Fields(
		"dev_mode", s.global.Development,
		"gossip_mode", s.global.Gossip.Enabled,
	).Info("configuring")

	s.logger.Fields(
		"hosts_dir", s.global.Storage.HostsDir,
		"cert_dir", s.global.Storage.CertsDir,
		"data_dir", s.global.Storage.DataDir,
	).Info("directories initialized")

	s.reaper = jack.NewReaper(
		woos.RouteCacheTTL,
		jack.ReaperWithLogger(s.logger),
		jack.ReaperWithHandler(func(ctx context.Context, id string) {
			if it, ok := cache.Route.Load(id); ok {
				if h, ok := it.Value.(*handlers.Route); ok {
					h.Close()
				}
			}
			cache.Route.Delete(id)
			s.logger.Fields("route_key", id).Debug("reaped idle route handler")
		}),
	)
	s.reaper.Start()

	if s.shutdown != nil {
		s.shutdown.RegisterFunc("RouteReaper", s.reaper.Stop)
	}

	if err := s.hostManager.ReloadFull(); err != nil {
		s.logger.Fields("err", err).Error("failed to load initial hosts")
		return err
	}
	hosts, _ := s.hostManager.LoadAll()
	s.logHostStats(hosts)

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
		if s.shutdown != nil {
			s.shutdown.RegisterFunc("Gossip", func() { _ = gs.Shutdown() })
		}
	}

	s.ipMiddleware = clientip.NewIPMiddleware(s.global.Security.TrustedProxies)
	s.rateLimiter = s.buildGlobalRateLimiter()

	s.skipLogPaths = make(map[string]bool)
	if len(s.global.Logging.Skip) > 0 {
		for _, p := range s.global.Logging.Skip {
			s.skipLogPaths[p] = true
		}
	}

	dataDir := woos.NewFolder(s.global.Storage.DataDir)
	s.firewall, err = firewall.New(s.global.Security.Firewall, dataDir, s.logger)
	if err != nil {
		return errors.Newf("firewall init: %w", err)
	}
	if s.firewall != nil && s.shutdown != nil {
		s.shutdown.RegisterFunc("Firewall", func() { _ = s.firewall.Close() })
	}

	s.startAdminServer()

	baseHandler := http.HandlerFunc(s.handleRequest)
	var httpFallbackHandler http.Handler = baseHandler
	if len(s.global.Bind.HTTPS) > 0 {
		httpFallbackHandler = http.HandlerFunc(s.redirectToHTTPS)
	}

	tlsCfg, acmeHandler, err := s.buildTLS(httpFallbackHandler)
	if err != nil {
		s.logger.Fields("err", err.Error()).Warn("TLS setup failed; HTTPS listeners may not start")
		tlsCfg = nil
		acmeHandler = httpFallbackHandler
	}

	if s.tlsManager != nil && s.shutdown != nil {
		s.shutdown.RegisterFunc("TLSManager", s.tlsManager.Close)
	}

	// Group TCP Routes by Listener Address
	tcpGroups := make(map[string][]*alaye.TCPRoute)
	for _, host := range hosts {
		for i := range host.Proxies {
			p := &host.Proxies[i]
			tcpGroups[p.Listen] = append(tcpGroups[p.Listen], p)
		}
	}

	for listen, routes := range tcpGroups {
		tp := tcp.NewProxy(listen, s.logger)
		for _, r := range routes {
			pattern := r.SNI
			if pattern == "" {
				pattern = "*"
			}
			tp.AddRoute(pattern, *r)
		}
		if err := tp.Start(); err != nil {
			s.logger.Fields("listen", listen, "err", err).Error("failed to start tcp proxy")
			continue
		}
		s.tcpProxies = append(s.tcpProxies, tp)
	}

	anyStreaming := s.hasStreaming(hosts)
	usedPorts := make(map[string]bool)

	for _, addr := range s.global.Bind.HTTP {
		_, port, _ := net.SplitHostPort(addr)
		usedPorts[port] = true
		s.startTCPServer(addr, false, nil, nil, baseHandler, acmeHandler, anyStreaming)
	}

	for _, addr := range s.global.Bind.HTTPS {
		_, port, _ := net.SplitHostPort(addr)
		usedPorts[port] = true
		s.startTCPServer(addr, true, nil, tlsCfg, baseHandler, acmeHandler, anyStreaming)
		s.startQUICServer(addr, nil, tlsCfg, baseHandler)
	}

	for _, h := range hosts {
		for _, port := range h.Bind {
			if usedPorts[port] {
				return errors.Newf("%w: %s is already in use by a global listener or another host", woos.ErrPortConflict, port)
			}
			usedPorts[port] = true

			addr := ":" + port
			isTLS := true
			if h.TLS.Mode == alaye.ModeLocalNone {
				isTLS = false
			}

			s.startTCPServer(addr, isTLS, h, tlsCfg, baseHandler, acmeHandler, anyStreaming)
			if isTLS {
				s.startQUICServer(addr, h, tlsCfg, baseHandler)
			}
		}
	}

	if len(s.servers) == 0 && len(s.tcpProxies) == 0 {
		return woos.ErrNoBindAddr
	}

	if s.shutdown != nil {
		s.shutdown.RegisterWithContext("Listeners", s.shutdownImpl)
	}

	errCh := make(chan error, len(s.servers))
	s.mu.RLock()
	for key, srv := range s.servers {
		go func(k string, server *http.Server) {
			s.logger.Fields("bind", server.Addr, "key", k).Info("listener starting")
			var err error
			if core.IsServerKeyTLS(k) {
				err = server.ListenAndServeTLS("", "")
			} else {
				err = server.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}(key, srv)
	}
	s.mu.RUnlock()

	select {
	case err := <-errCh:
		return err
	case <-s.shutdown.Done():
		return nil
	}
}

func (s *Server) shutdownImpl(ctx context.Context) error {
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}

	for _, tp := range s.tcpProxies {
		tp.Stop()
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	h3Done := make(chan struct{})
	go func() {
		s.h3Wg.Wait()
		close(h3Done)
	}()

	select {
	case <-h3Done:
		s.logger.Info("h3 connections drained successfully")
	case <-ctx.Done():
		s.logger.Warn("timeout waiting for h3 connections to drain")
	}

	for key, srv := range s.h3Servers {
		if err := srv.Close(); err != nil {
			s.logger.Fields("key", key, "err", err).Warn("h3 shutdown error")
		}
	}

	var wg sync.WaitGroup
	for key, srv := range s.servers {
		wg.Add(1)
		go func(k string, server *http.Server) {
			defer wg.Done()
			if err := server.Shutdown(ctx); err != nil {
				s.logger.Fields("key", k, "err", err).Error("listener shutdown error")
			} else {
				s.logger.Fields("key", k).Info("listener stopped")
			}
		}(key, srv)
	}
	wg.Wait()

	return nil
}

func (s *Server) logHostStats(hosts map[string]*alaye.Host) {
	hostCount := len(hosts)
	routeCount := 0
	tcpCount := 0
	for _, host := range hosts {
		routeCount += len(host.Routes)
		tcpCount += len(host.Proxies)
	}
	s.logger.Fields(
		"hosts", hostCount,
		"http_routes", routeCount,
		"tcp_routes", tcpCount,
	).Info("host configuration loaded")
}

func (s *Server) hasStreaming(hosts map[string]*alaye.Host) bool {
	for _, host := range hosts {
		for _, rt := range host.Routes {
			for _, srv := range rt.Backends.Servers {
				if srv.Streaming.Enabled {
					return true
				}
			}
		}
	}
	return false
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
		s.h3Wg.Add(1)
		defer s.h3Wg.Done()

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

	if s.firewall != nil {
		h = s.firewall.Handler(h)
	}

	if s.ipMiddleware != nil {
		h = s.ipMiddleware.Handler(h)
	}

	h = metrics.PrometheusMiddleware(s.hostManager)(h)
	h = recovery.New(s.logger)(h)

	return h
}

func (s *Server) Reload() {
	s.logger.Info("reloading configuration")

	sha, err := s.computeFullConfigSHA()
	if err != nil {
		s.logger.Warn("could not compute config sha: ", err)
		return
	}

	if sha == s.configSHA {
		s.logger.Info("reload requested: no configuration changes detected")
	} else {
		s.logger.Fields(
			"from", s.configSHA[:12],
			"to", sha[:12],
		).Infof("configuration changed")
		s.configSHA = sha
	}

	global, err := core.LoadGlobal(s.configPath)
	if err != nil {
		s.logger.Fields("err", err, "config_path", s.configPath).
			Error("reload config failed")
		return
	}

	absConfigPath, err := filepath.Abs(s.configPath)
	if err != nil {
		absConfigPath = s.configPath
	}

	woos.DefaultApply(global, absConfigPath)

	if s.global.Logging.Level != global.Logging.Level {
		s.logger.Infof("log_level: %s → %s",
			s.global.Logging.Level,
			global.Logging.Level,
		)
	}

	s.global = global

	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
	s.rateLimiter = s.buildGlobalRateLimiter()

	previousHosts, _ := s.hostManager.LoadAll()
	previousCount := len(previousHosts)

	if err := s.hostManager.ReloadFull(); err != nil {
		s.logger.Fields("err", err).Error("failed to reload hosts")
		return
	}

	newHosts, _ := s.hostManager.LoadAll()
	currentCount := len(newHosts)

	if s.tlsManager != nil {
		s.tlsManager.ClearCache()
	}

	s.mu.Lock()
	// Group TCP Routes by Listener Address for Reload
	tcpGroups := make(map[string][]*alaye.TCPRoute)
	for _, host := range newHosts {
		for i := range host.Proxies {
			p := &host.Proxies[i]
			tcpGroups[p.Listen] = append(tcpGroups[p.Listen], p)
		}
	}

	// Update existing proxies or start new ones (Note: dynamic start not fully implemented here for new ports, relies on existing listeners logic for now or full restart, but Route update is supported)
	for _, tp := range s.tcpProxies {
		_, port, _ := net.SplitHostPort(tp.Listen)
		if port == "" {
			if strings.HasPrefix(tp.Listen, ":") {
				port = tp.Listen[1:]
			} else {
				continue
			}
		}

		// Find the group for this proxy's listen address
		var group []*alaye.TCPRoute
		// Try exact match first
		if g, ok := tcpGroups[tp.Listen]; ok {
			group = g
		} else {
			// Try matching by port if Listen was :PORT
			for l, g := range tcpGroups {
				if strings.HasSuffix(l, ":"+port) {
					group = g
					break
				}
			}
		}

		if group == nil {
			// Listener removed in config? Disable all routes
			tp.UpdateRoutes(nil, nil)
			continue
		}

		newRoutes := make(map[string]*tcp.Balancer)
		var newDefault *tcp.Balancer

		for _, route := range group {
			bal := tcp.NewBalancer(*route)
			if route.SNI != "" {
				newRoutes[strings.ToLower(route.SNI)] = bal
			} else {
				// If Name is present but no SNI, treat as default if alone, or ignore?
				// User config: proxy "name" { listen=":X" } -> SNI defaults to empty -> "*"
				newDefault = bal
			}
		}
		tp.UpdateRoutes(newRoutes, newDefault)
	}
	s.mu.Unlock()

	s.logger.Fields(
		"previous_hosts", previousCount,
		"current_hosts", currentCount,
		"change", currentCount-previousCount,
	).Info("configuration reloaded successfully")
}

func (s *Server) buildGlobalRateLimiter() *ratelimit.RateLimiter {
	rlc := s.global.RateLimits

	if !rlc.Enabled || len(rlc.Rules) == 0 {
		return nil
	}

	ttl := core.Or(rlc.TTL, woos.DefaultRateLimitTTL)
	maxEntries := rlc.MaxEntries
	if maxEntries <= 0 {
		maxEntries = woos.DefaultRateLimitMaxEntries
	}

	policy := func(r *http.Request) (bucket string, pol ratelimit.RatePolicy, ok bool) {
		p := r.URL.Path

		if strings.HasPrefix(p, "/.well-known/acme-challenge/") {
			return woos.BucketACME, ratelimit.RatePolicy{}, false
		}

		for _, rule := range rlc.Rules {
			if len(rule.Methods) > 0 {
				methodMatch := false
				currentMethod := r.Method
				for _, m := range rule.Methods {
					if strings.EqualFold(m, currentMethod) {
						methodMatch = true
						break
					}
				}
				if !methodMatch {
					continue
				}
			}

			if len(rule.Prefixes) > 0 {
				prefixMatch := false
				for _, pref := range rule.Prefixes {
					if strings.HasPrefix(p, pref) {
						prefixMatch = true
						break
					}
				}
				if !prefixMatch {
					continue
				}
			}

			ruleName := rule.Name
			if ruleName == "" {
				ruleName = "global_default"
			}

			return ruleName, ratelimit.RatePolicy{
				Requests: rule.Requests,
				Window:   rule.Window,
				Burst:    rule.Burst,
				KeySpec:  rule.Key,
			}, true
		}

		return "", ratelimit.RatePolicy{}, false
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
		NextProtos:     []string{woos.AlpnTls, woos.AlpnH3, woos.AlpnH2, woos.AlpnH11},
		GetCertificate: s.tlsManager.GetCertificate,
	}

	return tlsCfg, httpHandler, nil
}

func (s *Server) logRequest(host string, r *http.Request, start time.Time, status int, bytes int64) {
	if s.logger == nil {
		return
	}

	if s.skipLogPaths[r.URL.Path] {
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
		fields = append(fields, "ua", core.Truncate(r.UserAgent(), 50))
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

	if r.URL.Path == "/favicon.ico" {
		s.serveDefaultFavicon(w, r)
		return
	}

	var host string
	var hcfg *alaye.Host

	if owner, ok := r.Context().Value(woos.OwnerKey).(*alaye.Host); ok && owner != nil {
		hcfg = owner
		if len(hcfg.Domains) > 0 {
			host = hcfg.Domains[0]
		} else {
			host = woos.PrivateBindingHost
		}
	} else {
		host = core.NormalizeHost(r.Host)
		hcfg = s.hostManager.Get(host)
	}

	if hcfg == nil {
		http.Error(w, "Hosting not found", http.StatusNotFound)
		s.logRequest(host, r, start, http.StatusNotFound, 0)
		return
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

func (s *Server) serveDefaultFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=31536000")
	if len(ui.Favicon) > 0 {
		http.ServeContent(w, r, "favicon.ico", ui.ModTime, bytes.NewReader(ui.Favicon))
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *Server) handleRoute(w http.ResponseWriter, r *http.Request, route *alaye.Route) {
	ctx := context.WithValue(r.Context(), woos.CtxOriginalPath, r.URL.Path)
	reqOut := r.WithContext(ctx)

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

	routeKey := route.Key()
	var handler http.Handler = s.getOrBuildRouteHandler(route, routeKey, &s.global.RateLimits)

	if route.Wasm != nil {
		wm, err := s.getWasmManager(route.Wasm, routeKey)
		if err != nil {
			s.logger.Fields("err", err, "module", route.Wasm.Module).Error("wasm: failed to load middleware")
			http.Error(w, "Internal Server Error (WASM)", http.StatusInternalServerError)
			return
		}
		handler = wm.Handler(handler)
	}

	if s.rateLimiter != nil {
		ignoreGlobal := false
		if route.RateLimit != nil && route.RateLimit.IgnoreGlobal {
			ignoreGlobal = true
		}
		if !ignoreGlobal {
			handler = s.rateLimiter.Handler(handler)
		}
	}

	handler.ServeHTTP(w, reqOut)
}

func (s *Server) getOrBuildRouteHandler(route *alaye.Route, key string, globalRate *alaye.GlobalRate) *handlers.Route {
	if it, ok := cache.Route.Load(key); ok {
		if h, ok := it.Value.(*handlers.Route); ok {
			s.reaper.Touch(key)
			return h
		}
	}

	h := handlers.NewRoute(route, globalRate, s.logger)

	newItem := &cache.Item{
		Value: h,
	}

	if it, loaded := cache.Route.LoadOrStore(key, newItem); loaded {
		h.Close()
		if existing, ok := it.Value.(*handlers.Route); ok {
			s.reaper.Touch(key)
			return existing
		}
	}

	s.reaper.Touch(key)
	return h
}

func (s *Server) getWasmManager(cfg *alaye.Wasm, key string) (*wasm.Manager, error) {
	if v, ok := s.wasmCache.Load(key); ok {
		return v.(*wasm.Manager), nil
	}

	mgr, err := wasm.NewManager(context.Background(), s.logger, cfg)
	if err != nil {
		return nil, err
	}

	if actual, loaded := s.wasmCache.LoadOrStore(key, mgr); loaded {
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

func (s *Server) computeFullConfigSHA() (string, error) {
	hasher := sha256.New()

	mainData, err := os.ReadFile(s.configPath)
	if err != nil {
		return "", err
	}
	hasher.Write(mainData)

	hostDir := s.global.Storage.HostsDir

	entries, err := os.ReadDir(hostDir)
	if err != nil {
		return "", err
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		files = append(files, e.Name())
	}

	sort.Strings(files)

	for _, name := range files {
		path := filepath.Join(hostDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		hasher.Write([]byte(name))
		hasher.Write(data)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
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
