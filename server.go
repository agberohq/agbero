package agbero

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/discovery/gossip"
	"git.imaxinacion.net/aibox/agbero/internal/handlers"
	"git.imaxinacion.net/aibox/agbero/internal/handlers/xtcp"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/clientip"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/firewall"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/h3"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/memory"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/observability"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/ratelimit"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/recovery"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/wasm"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/metrics"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/parser"
	tlss2 "git.imaxinacion.net/aibox/agbero/internal/pkg/tlss"
	"git.imaxinacion.net/aibox/agbero/internal/ui"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/mappo"
	"github.com/quic-go/quic-go/http3"
)

type Server struct {
	configPath string
	configSHA  string

	hostManager *discovery.Host
	global      *alaye.Global
	tlsManager  *tlss2.Manager

	firewall *firewall.Engine

	mu         sync.RWMutex
	servers    map[string]*http.Server
	h3Servers  map[string]*http3.Server
	tcpProxies []*xtcp.Proxy

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

	if configPath != "" {
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
	} else {
		woos.DefaultApply(s.global, ".")
		s.logger.Info("starting in ephemeral mode")
	}

	s.logger.Fields(
		"dev_mode", s.global.Development,
		"gossip_mode", s.global.Gossip.Enabled.Active(),
	).Info("configuring")

	if configPath != "" {
		s.logger.Fields(
			"hosts_dir", s.global.Storage.HostsDir,
			"cert_dir", s.global.Storage.CertsDir,
			"data_dir", s.global.Storage.DataDir,
		).Info("directories initialized")
	}

	if err := s.validateTLSConfig(); err != nil {
		s.logger.Fatal(err)
		return err
	}

	s.reaper = jack.NewReaper(
		woos.RouteCacheTTL,
		jack.ReaperWithLogger(s.logger),
		jack.ReaperWithHandler(func(ctx context.Context, id string) {
			if it, ok := zulu.Route.Load(id); ok {
				if h, ok := it.Value.(*handlers.Route); ok {
					h.Close()
				}
			}
			zulu.Route.Delete(id)
			s.logger.Fields("route_key", id).Debug("reaped idle route handler")
		}),
	)
	s.reaper.Start()

	if s.shutdown != nil {
		s.shutdown.RegisterFunc("RouteReaper", s.reaper.Stop)
	}

	if configPath != "" {
		if err := s.hostManager.ReloadFull(); err != nil {
			s.logger.Fields("err", err).Error("failed to load initial hosts")
			return err
		}
	}

	hosts, _ := s.hostManager.LoadAll()
	s.logHostStats(hosts)

	if s.global.Gossip.Enabled.Active() {
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

	var trustedProxies []string
	if s.global.Security.Enabled.Active() {
		trustedProxies = s.global.Security.TrustedProxies
	}
	s.ipMiddleware = clientip.NewIPMiddleware(trustedProxies)
	s.rateLimiter = s.buildGlobalRateLimiter()

	s.skipLogPaths = make(map[string]bool)
	if s.global.Logging.Enabled.Active() && len(s.global.Logging.Skip) > 0 {
		for _, p := range s.global.Logging.Skip {
			s.skipLogPaths[p] = true
		}
	}

	if s.global.Security.Enabled.Active() {
		fwConfig := s.global.Security.Firewall
		if fwConfig.Status.Active() {
			dataDir := woos.NewFolder(s.global.Storage.DataDir)
			var err error
			s.firewall, err = firewall.New(&fwConfig, dataDir, s.logger)
			if err != nil {
				return errors.Newf("firewall init: %w", err)
			}
			if s.shutdown != nil {
				s.shutdown.RegisterFunc("Firewall", func() { _ = s.firewall.Close() })
			}
		}
	}

	s.startAdminServer()

	baseHandler := http.HandlerFunc(s.handleRequest)
	var httpFallbackHandler http.Handler = baseHandler
	if len(s.global.Bind.HTTPS) > 0 {
		httpFallbackHandler = http.HandlerFunc(s.redirectToHTTPS)
	}

	tlsCfg, acmeHandler, err := s.buildTLS(httpFallbackHandler)
	if err != nil {
		if configPath != "" {
			s.logger.Fields("err", err.Error()).Warn("TLS setup failed; HTTPS listeners may not start")
		}
		tlsCfg = nil
		acmeHandler = httpFallbackHandler
	}

	if s.tlsManager != nil && s.shutdown != nil {
		s.shutdown.RegisterFunc("TLSManager", s.tlsManager.Close)
	}

	tcpGroups := make(map[string][]alaye.TCPRoute)
	for _, host := range hosts {
		for i := range host.Proxies {
			p := host.Proxies[i]
			tcpGroups[p.Listen] = append(tcpGroups[p.Listen], p)
		}
	}

	for listen, routes := range tcpGroups {
		tp := xtcp.NewProxy(listen, s.logger)
		for _, r := range routes {
			pattern := r.SNI
			if pattern == "" {
				pattern = "*"
			}
			tp.AddRoute(pattern, r)
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
			if zulu.IsServerKeyTLS(k) {
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

func (s *Server) Reload() {
	if s.configPath == "" {
		s.logger.Info("reload ignored in ephemeral mode")
		return
	}

	s.logger.Info("reloading configuration")

	sha, err := s.computeFullConfigSHA()
	if err != nil {
		s.logger.Warn("could not compute config sha: ", err)
		return
	}

	if sha == s.configSHA {
		s.logger.Info("reload requested: no configuration changes detected")
		return
	}

	s.logger.Fields(
		"from", s.configSHA[:12],
		"to", sha[:12],
	).Infof("configuration changed")

	global, err := parser.LoadGlobal(s.configPath)
	if err != nil {
		s.logger.Fields("err", err, "config_path", s.configPath).
			Error("reload config failed")
		return
	}

	if s.global.Logging.Diff.Active() {
		for _, v := range zulu.Diff(s.global, global) {
			s.logger.Debug(v)
		}
	}

	absConfigPath, err := filepath.Abs(s.configPath)
	if err != nil {
		absConfigPath = s.configPath
	}
	woos.DefaultApply(global, absConfigPath)

	previousHosts, _ := s.hostManager.LoadAll()
	previousCount := len(previousHosts)

	if err := s.hostManager.ReloadFull(); err != nil {
		s.logger.Fields("err", err).Error("failed to reload hosts")
		return
	}

	newHosts, _ := s.hostManager.LoadAll()
	currentCount := len(newHosts)

	validKeys := make(map[string]bool)
	for _, h := range newHosts {
		for _, r := range h.Routes {
			rKey := r.Key()
			if r.Backends.Enabled.Active() {
				for _, srv := range r.Backends.Servers {
					validKeys[fmt.Sprintf("%s|%s", rKey, srv.Address)] = true
				}
			}
		}
		for _, proxy := range h.Proxies {
			sni := proxy.SNI
			for _, srv := range proxy.Backends {
				validKeys[fmt.Sprintf("tcp|%s|%s|%s", proxy.Listen, sni, srv.Address)] = true
			}
		}
	}

	tcpGroups := make(map[string][]alaye.TCPRoute)
	for _, host := range newHosts {
		for i := range host.Proxies {
			p := host.Proxies[i]
			tcpGroups[p.Listen] = append(tcpGroups[p.Listen], p)
		}
	}

	newRateLimiter := s.buildGlobalRateLimiter()

	var newFirewall *firewall.Engine
	if global.Security.Enabled.Active() {
		fwConfig := global.Security.Firewall
		dataDir := woos.NewFolder(global.Storage.DataDir)
		newFirewall, _ = firewall.New(&fwConfig, dataDir, s.logger)
	}

	s.mu.Lock()
	if s.global.Logging.Level != global.Logging.Level {
		s.logger.Infof("log_level: %s → %s", s.global.Logging.Level, global.Logging.Level)
	}
	s.configSHA = sha
	s.global = global

	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
	s.rateLimiter = newRateLimiter

	if s.firewall != nil {
		s.firewall.Close()
	}
	s.firewall = newFirewall

	for _, tp := range s.tcpProxies {
		_, port, _ := net.SplitHostPort(tp.Listen)
		if port == "" {
			if strings.HasPrefix(tp.Listen, ":") {
				port = tp.Listen[1:]
			} else {
				continue
			}
		}

		var group []alaye.TCPRoute
		if g, ok := tcpGroups[tp.Listen]; ok {
			group = g
		} else {
			for l, g := range tcpGroups {
				if strings.HasSuffix(l, ":"+port) {
					group = g
					break
				}
			}
		}

		if group == nil {
			tp.UpdateRoutes(nil, nil)
			continue
		}

		newRoutes := make(map[string]*xtcp.Balancer)
		var newDefault *xtcp.Balancer

		for _, route := range group {
			bal := xtcp.NewBalancer(route, metrics.DefaultRegistry)
			if route.SNI != "" {
				newRoutes[strings.ToLower(route.SNI)] = bal
			} else {
				newDefault = bal
			}
		}
		tp.UpdateRoutes(newRoutes, newDefault)
	}

	if s.tlsManager != nil {
		s.tlsManager.ClearCache()
	}

	s.mu.Unlock()

	metrics.DefaultRegistry.Prune(validKeys)

	s.logger.Fields(
		"previous_hosts", previousCount,
		"current_hosts", currentCount,
		"change", currentCount-previousCount,
	).Info("configuration reloaded successfully")
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
		if err := srv.Shutdown(ctx); err != nil {
			s.logger.Fields("key", key, "err", err).Warn("h3 graceful shutdown failed")
			_ = srv.Close()
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
			if rt.Backends.Enabled.Active() {
				for _, srv := range rt.Backends.Servers {
					if srv.Streaming.Enabled.Active() && srv.Streaming.Enabled.Active() {
						return true
					}
				}
			}
		}
	}
	return false
}

func (s *Server) applyMTLS(cfg *tls.Config, host *alaye.Host) {
	if host.TLS.ClientAuth == "" && len(host.TLS.ClientCAs) == 0 {
		return
	}

	switch strings.ToLower(host.TLS.ClientAuth) {
	case alaye.TlsRequest:
		cfg.ClientAuth = tls.RequestClientCert
	case alaye.TlsRequire:
		cfg.ClientAuth = tls.RequireAnyClientCert
	case alaye.TlsVerifyIfGiven:
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	case alaye.TlsRequireAndVerify:
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	default:
		cfg.ClientAuth = tls.NoClientCert
	}

	if len(host.TLS.ClientCAs) > 0 {
		pool := x509.NewCertPool()
		for _, path := range host.TLS.ClientCAs {
			if pem, err := os.ReadFile(path); err == nil {
				pool.AppendCertsFromPEM(pem)
			} else {
				s.logger.Warnf("failed to read client CA %s: %v", path, err)
			}
		}
		cfg.ClientCAs = pool
	}
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
		ctx = context.WithValue(ctx, woos.CtxPort, port)
		if owner != nil {
			ctx = context.WithValue(ctx, woos.OwnerKey, owner)
		}
		handler.ServeHTTP(w, r.WithContext(ctx))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           wrappedHandler,
		ReadTimeout:       s.global.Timeouts.Read,
		WriteTimeout:      s.global.Timeouts.Write,
		IdleTimeout:       s.global.Timeouts.Idle,
		ReadHeaderTimeout: s.global.Timeouts.ReadHeader,
		MaxHeaderBytes:    s.global.General.MaxHeaderBytes,
	}

	if isTLS && tlsCfg != nil {
		if owner != nil {
			localCfg := tlsCfg.Clone()
			s.applyMTLS(localCfg, owner)
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

	key := zulu.ServerKey(addr, isTLS)
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
		ctx = context.WithValue(ctx, woos.CtxPort, port)
		if owner != nil {
			ctx = context.WithValue(ctx, woos.OwnerKey, owner)
		}
		handler.ServeHTTP(w, r.WithContext(ctx))
	})

	serverTLSCfg := tlsCfg
	if owner != nil {
		localCfg := tlsCfg.Clone()
		s.applyMTLS(localCfg, owner)
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
	h := memory.Middleware(next)

	if advertiseH3 {
		h = h3.AdvertiseHTTP3(port)(h)
	}

	if s.firewall != nil {
		h = s.firewall.Handler(h, nil)
	}

	if s.ipMiddleware != nil {
		h = s.ipMiddleware.Handler(h)
	}

	if s.global.Logging.Prometheus.Enabled.Active() {
		h = observability.Prometheus(s.hostManager)(h)
	}

	h = recovery.New(s.logger)(h)
	return h
}

func (s *Server) buildGlobalRateLimiter() *ratelimit.RateLimiter {
	rlc := s.global.RateLimits

	if !rlc.Enabled.Active() || len(rlc.Rules) == 0 {
		return nil
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

	return ratelimit.NewRateLimiter(rlc.TTL, rlc.MaxEntries, policy)
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

	s.tlsManager = tlss2.NewManager(s.logger, s.hostManager, s.global)

	httpHandler, err := s.tlsManager.EnsureCertMagic(next)
	if err != nil {
		s.logger.Fields("err", err.Error()).Warn("certmagic not enabled; using HTTP handler without ACME")
		httpHandler = next
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		NextProtos:         []string{woos.AlpnTls, woos.AlpnH3, woos.AlpnH2, woos.AlpnH11},
		GetConfigForClient: s.tlsManager.GetConfigForClient,
	}

	return tlsCfg, httpHandler, nil
}

func (s *Server) validateTLSConfig() error {
	if !s.global.Development {
		return nil
	}

	for _, addr := range s.global.Bind.HTTPS {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		if !woos.IsLocalhost(host) && host != "" && host != "0.0.0.0" && host != "::" {
			continue
		}

		hosts, _ := s.hostManager.LoadAll()
		for _, h := range hosts {
			for _, bindPort := range h.Bind {
				if bindPort == port {
					switch h.TLS.Mode {
					case alaye.ModeLocalAuto, alaye.ModeLocalCert:
						certDir := woos.MakeFolder(s.global.Storage.CertsDir, woos.CertDir)
						if !tlss2.IsCARootInstalled(certDir.Path()) {
							return errors.Newf(
								"HTTPS binding on %s requires local CA. Run: agbero cert install",
								addr,
							)
						}
					}
					break
				}
			}
		}
	}
	return nil
}

func (s *Server) logRequest(host string, r *http.Request, start time.Time, status int, bytes int64) {
	if s.logger == nil {
		return
	}

	if s.skipLogPaths[r.URL.Path] {
		return
	}

	fields := []any{
		"host", host,
		"path", r.URL.Path,
		"remote", clientip.ClientIP(r),
		"duration", time.Since(start),
		"proto", r.Proto,
		"status", status,
		"bytes", bytes,
	}

	if port, ok := r.Context().Value(woos.CtxPort).(string); ok && port != "" {
		fields = append(fields, "port", port)
	}

	if s.global != nil && s.shouldLogUserAgent(r) {
		fields = append(fields, "ua", zulu.Truncate(r.UserAgent(), 50))
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
		host = zulu.NormalizeHost(r.Host)
		hcfg = s.hostManager.Get(host)
	}

	if hcfg == nil {
		http.Error(w, "Hosting not found", http.StatusNotFound)
		s.logRequest(host, r, start, http.StatusNotFound, 0)
		return
	}

	maxBody := int64(alaye.DefaultMaxBodySize)
	if hcfg.Limits.MaxBodySize > 0 {
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
		rw := &zulu.ResponseWriter{ResponseWriter: w, StatusCode: 200}
		// Pass hcfg.Domains
		s.handleRoute(rw, r, res.Route, hcfg.Domains)
		s.logRequest(host, r, start, rw.StatusCode, rw.BytesWritten)
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

func (s *Server) handleRoute(w http.ResponseWriter, r *http.Request, route *alaye.Route, domains []string) {
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
			if after, ok := strings.CutPrefix(reqOut.URL.Path, prefix); ok {
				reqOut.URL.Path = after
				if reqOut.URL.Path == "" {
					reqOut.URL.Path = "/"
				}
				reqOut.URL.RawPath = ""
				break
			}
		}
	}

	routeKey := route.Key()
	// Pass domains
	var handler http.Handler = s.getOrBuildRouteHandler(route, routeKey, domains)

	if route.Wasm.Enabled.Active() {
		wm, err := s.getWasmManager(&route.Wasm, routeKey)
		if err != nil {
			s.logger.Fields("err", err, "module", route.Wasm.Module).Error("wasm: failed to load middleware")
			http.Error(w, "Internal Server Error (WASM)", http.StatusInternalServerError)
			return
		}
		handler = wm.Handler(handler)
	}

	if s.rateLimiter != nil {
		ignoreGlobal := false
		if route.RateLimit.IgnoreGlobal {
			ignoreGlobal = true
		}
		if !ignoreGlobal {
			handler = s.rateLimiter.Handler(handler)
		}
	}

	handler.ServeHTTP(w, reqOut)
}

func (s *Server) getOrBuildRouteHandler(route *alaye.Route, key string, domains []string) *handlers.Route {
	if it, ok := zulu.Route.Load(key); ok {
		if h, ok := it.Value.(*handlers.Route); ok {
			s.reaper.Touch(key)
			return h
		}
	}

	// Pass domains
	h := handlers.NewRoute(s.global, route, domains, s.logger)
	newItem := &mappo.Item{
		Value: h,
	}

	if it, loaded := zulu.Route.LoadOrStore(key, newItem); loaded {
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

	if owner, ok := r.Context().Value(woos.OwnerKey).(*alaye.Host); ok && owner != nil {
		for _, bindPort := range owner.Bind {
			if bindPort != "" {
				target := fmt.Sprintf("https://%s:%s%s", host, bindPort, r.URL.RequestURI())
				http.Redirect(w, r, target, http.StatusMovedPermanently)
				return
			}
		}
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
		return hex.EncodeToString(hasher.Sum(nil)), nil
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
