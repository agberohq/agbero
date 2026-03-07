package agbero

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/cluster"
	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"git.imaxinacion.net/aibox/agbero/internal/handlers"
	"git.imaxinacion.net/aibox/agbero/internal/handlers/xtcp"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/firewall"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/h3"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/memory"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/observability"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/ratelimit"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/recovery"
	"git.imaxinacion.net/aibox/agbero/internal/middleware/wasm"
	"git.imaxinacion.net/aibox/agbero/internal/operation"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/metrics"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/parser"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/security"
	tlss2 "git.imaxinacion.net/aibox/agbero/internal/pkg/tlss"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/wellknown"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/mappo"
	"github.com/quic-go/quic-go/http3"
)

// =============================================================================
// Server Configuration
// =============================================================================

type config struct {
	addr        string
	isTLS       bool
	streaming   bool
	port        string
	tlsConfig   *tls.Config
	baseHandler http.Handler
	acmeHandler http.Handler
	hostManager *discovery.Host
}

// =============================================================================
// Server Structure
// =============================================================================

type Server struct {
	configPath string
	configSHA  string

	hostManager     *discovery.Host
	global          *alaye.Global
	tlsManager      *tlss2.Manager
	securityManager *security.Manager

	firewall *firewall.Engine

	mu         sync.RWMutex
	servers    map[string]*http.Server
	h3Servers  map[string]*http3.Server
	tcpProxies []*xtcp.Proxy

	connTrackers map[string]*connTracker

	activeBaseHandler http.Handler
	activeAcmeHandler http.Handler
	activeTlsConfig   *tls.Config

	logger *ll.Logger

	ipMgr          *zulu.IPManager
	rateLimiter    *ratelimit.RateLimiter
	clusterManager *cluster.Manager

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
		servers:      make(map[string]*http.Server),
		h3Servers:    make(map[string]*http3.Server),
		connTrackers: make(map[string]*connTracker),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// =============================================================================
// Cluster Integration Handlers
// =============================================================================

func (s *Server) OnClusterChange(key string, value []byte, deleted bool) {
	if s.hostManager != nil {
		s.hostManager.OnClusterChange(key, value, deleted)
	}
}

func (s *Server) OnClusterCert(domain string, certPEM, keyPEM []byte) error {
	if s.tlsManager != nil {
		return s.tlsManager.ApplyClusterCertificate(domain, certPEM, keyPEM)
	}
	return nil
}

func (s *Server) OnClusterChallenge(token, keyAuth string, deleted bool) {
	if s.tlsManager != nil {
		s.tlsManager.ApplyClusterChallenge(token, keyAuth, deleted)
	}
}

// =============================================================================
// Server Lifecycle: Start
// =============================================================================

func (s *Server) Start(configPath string) error {
	s.mu.Lock()
	s.configPath = configPath
	s.mu.Unlock()

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

		sha, err := s.configComputeSHA()
		if err != nil {
			s.logger.Warn("could not compute config sha: ", err)
		} else {
			s.mu.Lock()
			s.configSHA = sha
			s.mu.Unlock()
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
		"cluster_mode", s.global.Gossip.Enabled.Active(),
	).Info("configuring")

	if configPath != "" {
		s.logger.Fields(
			"hosts_dir", s.global.Storage.HostsDir,
			"cert_dir", s.global.Storage.CertsDir,
			"data_dir", s.global.Storage.DataDir,
		).Info("directories initialized")
	}

	if s.global.Security.Enabled.Active() && s.global.Security.InternalAuthKey != "" {
		mgr, err := security.LoadKeys(s.global.Security.InternalAuthKey)
		if err != nil {
			s.logger.Fields("err", err, "key_file", s.global.Security.InternalAuthKey).Error("failed to load internal auth key")
			return err
		}
		s.securityManager = mgr
		s.logger.Info("internal security manager initialized")
	} else if s.global.API.Enabled.Active() {
		s.logger.Warn("API enabled but security.internal_auth_key not set; API endpoints may fail auth")
	}

	if err := s.tlsValidate(); err != nil {
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
		cfg := cluster.Config{
			Name:     s.global.Admin.Address,
			BindAddr: "",
			BindPort: s.global.Gossip.Port,
			Secret:   []byte(s.global.Gossip.SecretKey),
			Seeds:    s.global.Gossip.Seeds,
		}

		if cfg.Name == "" || strings.HasPrefix(cfg.Name, ":") {
			hostname, _ := os.Hostname()
			cfg.Name = fmt.Sprintf("agbero-%s-%d", hostname, s.global.Gossip.Port)
		}

		cm, err := cluster.NewManager(cfg, s, s.logger)
		if err != nil {
			return errors.Newf("failed to start cluster manager: %w", err)
		}
		s.clusterManager = cm

		if s.shutdown != nil {
			s.shutdown.RegisterFunc("Cluster", func() { _ = s.clusterManager.Shutdown() })
		}
	}

	var trustedProxies []string
	if s.global.Security.Enabled.Active() {
		trustedProxies = s.global.Security.TrustedProxies
	}

	s.ipMgr = zulu.NewIPManager(trustedProxies)
	s.rateLimiter = s.chainBuildRateLimiter(s.global, s.ipMgr)

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
			s.firewall, err = firewall.New(firewall.Config{
				Firewall: &fwConfig, DataDir: dataDir, Logger: s.logger, IPMgr: s.ipMgr,
			})
			if err != nil {
				return errors.Newf("firewall init: %w", err)
			}
			if s.shutdown != nil {
				s.shutdown.RegisterFunc("Firewall", func() { _ = s.firewall.Close() })
			}
		}
	}

	s.startAdminServer()

	s.activeBaseHandler = http.HandlerFunc(s.handleRequest)
	s.activeAcmeHandler = s.activeBaseHandler

	if len(s.global.Bind.HTTPS) > 0 {
		s.activeAcmeHandler = http.HandlerFunc(s.redirectToHTTPS)
	}

	tlsCfg, acmeHandler := s.tlsBuild(s.activeAcmeHandler)
	s.activeTlsConfig = tlsCfg

	if s.tlsManager != nil {
		if s.shutdown != nil {
			s.shutdown.RegisterFunc("TLSManager", s.tlsManager.Close)
		}

		if s.clusterManager != nil {
			s.tlsManager.SetUpdateCallback(func(domain string, certPEM, keyPEM []byte) {
				if err := s.clusterManager.BroadcastCert(domain, certPEM, keyPEM); err != nil {
					s.logger.Fields("domain", domain, "err", err).Error("failed to broadcast certificate")
				} else {
					s.logger.Fields("domain", domain).Info("broadcasted certificate to cluster")
				}
			})
		}
	}

	s.tcpStartProxy(hosts)

	anyStreaming := anyStreamingEnabled(hosts)
	usedPorts := make(map[string]bool)

	for _, addr := range s.global.Bind.HTTP {
		if !strings.Contains(addr, ":") {
			addr = ":" + addr
		}
		_, port, _ := net.SplitHostPort(addr)
		usedPorts[port] = true
		srv, key, _ := s.serverCreate(config{
			addr:        addr,
			isTLS:       false,
			tlsConfig:   nil,
			baseHandler: s.activeBaseHandler,
			acmeHandler: acmeHandler,
			streaming:   anyStreaming,
			port:        port,
			hostManager: s.hostManager,
		})
		s.mu.Lock()
		s.servers[key] = srv
		s.mu.Unlock()
	}

	for _, addr := range s.global.Bind.HTTPS {
		if !strings.Contains(addr, ":") {
			addr = ":" + addr
		}
		_, port, _ := net.SplitHostPort(addr)
		usedPorts[port] = true
		srv, key, tracker := s.serverCreate(config{
			addr:        addr,
			isTLS:       true,
			tlsConfig:   s.activeTlsConfig,
			baseHandler: s.activeBaseHandler,
			acmeHandler: acmeHandler,
			streaming:   anyStreaming,
			port:        port,
			hostManager: s.hostManager,
		})
		s.mu.Lock()
		s.servers[key] = srv
		s.connTrackers[addr] = tracker
		s.mu.Unlock()

		h3, h3Key := s.serverCreateQUIC(addr, s.activeTlsConfig, s.activeBaseHandler, port)
		if h3 != nil {
			s.mu.Lock()
			s.h3Servers[h3Key] = h3
			s.mu.Unlock()
			s.serverRunQUIC(h3, addr)
		}
	}

	for _, h := range hosts {
		for _, port := range h.Bind {
			if usedPorts[port] {
				s.logger.Fields("port", port, "host", h.Domains).Warn("port shared by multiple hosts; skipping duplicate listener")
				continue
			}
			usedPorts[port] = true

			addr := port
			if !strings.Contains(port, ":") {
				addr = ":" + port
			}

			isTLS := true
			if h.TLS.Mode == alaye.ModeLocalNone {
				isTLS = false
			}

			srv, key, tracker := s.serverCreate(config{
				addr:        addr,
				isTLS:       isTLS,
				tlsConfig:   s.activeTlsConfig,
				baseHandler: s.activeBaseHandler,
				acmeHandler: acmeHandler,
				streaming:   anyStreaming,
				port:        port,
				hostManager: s.hostManager,
			})
			s.mu.Lock()
			s.servers[key] = srv
			if isTLS {
				s.connTrackers[addr] = tracker
			}
			s.mu.Unlock()

			if isTLS {
				h3, h3Key := s.serverCreateQUIC(addr, s.activeTlsConfig, s.activeBaseHandler, port)
				if h3 != nil {
					s.mu.Lock()
					s.h3Servers[h3Key] = h3
					s.mu.Unlock()
					s.serverRunQUIC(h3, addr)
				}
			}
		}
	}

	if len(s.servers) == 0 && len(s.tcpProxies) == 0 {
		return woos.ErrNoBindAddr
	}

	select {
	case <-s.hostManager.Changed():
	default:
	}

	if configPath != "" {
		go s.serverWatchConfig()
	}

	if s.shutdown != nil {
		s.shutdown.RegisterWithContext("Listeners", s.shutdownImpl)
	}

	return s.serverAwaitErrors()
}

// =============================================================================
// Server Lifecycle: Reload
// =============================================================================

func (s *Server) Reload() {
	s.mu.RLock()
	configPath := s.configPath
	s.mu.RUnlock()

	if configPath == "" {
		s.logger.Info("reload ignored in ephemeral mode")
		return
	}

	s.logger.Info("reloading configuration")

	sha, err := s.configComputeSHA()
	if err != nil {
		s.logger.Warn("could not compute config sha: ", err)
		return
	}

	s.mu.RLock()
	currentSHA := s.configSHA
	s.mu.RUnlock()

	if sha == currentSHA {
		s.logger.Info("reload requested: no configuration changes detected")
		return
	}

	s.logger.Fields(
		"from", currentSHA[:12],
		"to", sha[:12],
	).Infof("configuration changed")

	s.wasmCleanup()

	global, err := parser.LoadGlobal(configPath)
	if err != nil {
		s.logger.Fields("err", err, "config_path", configPath).
			Error("reload config failed")
		return
	}

	if s.global.Logging.Diff.Active() {
		for _, v := range zulu.Diff(s.global, global) {
			s.logger.Debug(v)
		}
	}

	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		absConfigPath = configPath
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

	validKeys := s.configBuildRoute(newHosts)
	tcpGroups := groupTCPRoutesByListen(newHosts)

	var trustedProxies []string
	if global.Security.Enabled.Active() {
		trustedProxies = global.Security.TrustedProxies
	}
	newIPMgr := zulu.NewIPManager(trustedProxies)
	newRateLimiter := s.chainBuildRateLimiter(global, newIPMgr)

	s.mu.Lock()
	s.configApplyReload(global, sha, newIPMgr, newRateLimiter)
	s.startNewListeners(global, newHosts)
	s.tcpUpdateProxy(tcpGroups)
	s.mu.Unlock()

	metrics.DefaultRegistry.Prune(validKeys)

	s.logger.Fields(
		"previous_hosts", previousCount,
		"current_hosts", currentCount,
		"change", currentCount-previousCount,
	).Info("configuration reloaded successfully")
}

// =============================================================================
// Server Lifecycle: Shutdown
// =============================================================================

func (s *Server) shutdownImpl(ctx context.Context) error {
	if s.clusterManager != nil {
		s.clusterManager.BroadcastStatus("draining")
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
		}
	}

	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}

	for _, tp := range s.tcpProxies {
		tp.Stop()
	}

	s.waitForHTTPConnections(ctx)
	s.waitForH3Connections(ctx)
	s.shutdownH3Servers(ctx)
	s.shutdownHTTPServers(ctx)

	return nil
}

// =============================================================================
// Connection Draining Helpers
// =============================================================================

func (s *Server) waitForHTTPConnections(ctx context.Context) {
	s.mu.RLock()
	var trackerWg sync.WaitGroup
	for _, t := range s.connTrackers {
		trackerWg.Add(1)
		go func(ct *connTracker) {
			defer trackerWg.Done()
			ct.wait()
		}(t)
	}
	s.mu.RUnlock()

	done := make(chan struct{})
	go func() {
		trackerWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("connections drained")
	case <-ctx.Done():
		s.logger.Warn("timeout waiting for connections to drain")
	}
}

func (s *Server) waitForH3Connections(ctx context.Context) {
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
}

func (s *Server) shutdownH3Servers(ctx context.Context) {
	for key, srv := range s.h3Servers {
		if err := srv.Shutdown(ctx); err != nil {
			s.logger.Fields("key", key, "err", err).Warn("h3 graceful shutdown failed")
			_ = srv.Close()
		}
	}
}

func (s *Server) shutdownHTTPServers(ctx context.Context) {
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
}

// =============================================================================
// TCP Proxy Management
// =============================================================================

func (s *Server) tcpStartProxy(hosts map[string]*alaye.Host) {
	tcpGroups := groupTCPRoutesByListen(hosts)

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
}

func (s *Server) tcpUpdateProxy(tcpGroups map[string][]alaye.TCPRoute) {
	for _, tp := range s.tcpProxies {
		group := findTCPGroupForProxy(tp, tcpGroups)
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

	for listen, group := range tcpGroups {
		exists := false
		for _, tp := range s.tcpProxies {
			if tp.Listen == listen {
				exists = true
				break
			}
		}

		if !exists {
			tp := xtcp.NewProxy(listen, s.logger)
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

			if err := tp.Start(); err != nil {
				s.logger.Fields("listen", listen, "err", err).Error("failed to start new tcp proxy on reload")
			} else {
				s.tcpProxies = append(s.tcpProxies, tp)
			}
		}
	}
}

// =============================================================================
// Server Creation
// =============================================================================

func (s *Server) serverCreate(cfg config) (*http.Server, string, *connTracker) {
	var handler http.Handler
	if cfg.isTLS {
		handler = s.chainBuild(cfg.baseHandler, true, cfg.port)
	} else {
		handler = s.chainBuild(cfg.acmeHandler, false, "")
	}

	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, woos.CtxPort, cfg.port)

		if owner := cfg.hostManager.GetByPort(cfg.port); owner != nil {
			ctx = context.WithValue(ctx, woos.OwnerKey, owner)
		}

		handler.ServeHTTP(w, r.WithContext(ctx))
	})

	tracker := newConnTracker()
	srv := &http.Server{
		Addr:              cfg.addr,
		Handler:           wrappedHandler,
		ReadTimeout:       s.global.Timeouts.Read,
		WriteTimeout:      s.global.Timeouts.Write,
		IdleTimeout:       s.global.Timeouts.Idle,
		ReadHeaderTimeout: s.global.Timeouts.ReadHeader,
		MaxHeaderBytes:    s.global.General.MaxHeaderBytes,
		ErrorLog:          log.New(&llWriter{logger: s.logger}, "", 0),
		ConnState:         tracker.track,
	}

	if cfg.isTLS && cfg.tlsConfig != nil {
		localCfg := cfg.tlsConfig.Clone()
		localCfg.GetConfigForClient = nil

		localCfg.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if chi.ServerName != "" {
				cert, err := s.tlsManager.GetCertificate(chi)
				if err == nil {
					return cert, nil
				}
			}

			owner := cfg.hostManager.GetByPort(cfg.port)
			if owner != nil && len(owner.Domains) > 0 {
				fallbackChi := *chi
				fallbackChi.ServerName = owner.Domains[0]
				cert, err := s.tlsManager.GetCertificate(&fallbackChi)
				if err == nil {
					return cert, nil
				}
				return nil, err
			}

			return nil, fmt.Errorf("no certificate found")
		}
		srv.TLSConfig = localCfg
	}

	key := zulu.ServerKey(cfg.addr, cfg.isTLS)
	return srv, key, tracker
}

func (s *Server) serverCreateQUIC(addr string, tlsCfg *tls.Config, baseHandler http.Handler, port string) (*http3.Server, string) {
	if tlsCfg == nil {
		return nil, ""
	}

	handler := s.chainBuild(baseHandler, false, "")

	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.h3Wg.Add(1)
		defer s.h3Wg.Done()

		ctx := r.Context()
		ctx = context.WithValue(ctx, woos.CtxPort, port)
		if owner := s.hostManager.GetByPort(port); owner != nil {
			ctx = context.WithValue(ctx, woos.OwnerKey, owner)
		}
		handler.ServeHTTP(w, r.WithContext(ctx))
	})

	serverTLSCfg := tlsCfg.Clone()
	serverTLSCfg.GetConfigForClient = nil

	serverTLSCfg.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if chi.ServerName != "" {
			cert, err := s.tlsManager.GetCertificate(chi)
			if err == nil {
				return cert, nil
			}
		}

		owner := s.hostManager.GetByPort(port)
		if owner != nil && len(owner.Domains) > 0 {
			fallbackChi := *chi
			fallbackChi.ServerName = owner.Domains[0]
			cert, err := s.tlsManager.GetCertificate(&fallbackChi)
			if err == nil {
				return cert, nil
			}
			return nil, err
		}
		return nil, fmt.Errorf("no certificate found")
	}

	h3Server := &http3.Server{
		Addr:      addr,
		Handler:   wrappedHandler,
		TLSConfig: serverTLSCfg,
	}

	key := woos.H3KeyPrefix + addr
	return h3Server, key
}

func (s *Server) serverRunQUIC(h3Server *http3.Server, addr string) {
	go func() {
		s.logger.Fields("bind", addr, "proto", "h3").Info("listener starting")
		if err := h3Server.ListenAndServe(); err != nil {
			s.logger.Fields("err", err, "proto", "h3").Warn("h3 listener stopped")
		}
	}()
}

func (s *Server) serverStartAsync(key string, srv *http.Server) {
	go func(k string, server *http.Server) {
		s.logger.Fields("bind", server.Addr, "key", k).Info("listener started (reload)")
		var err error
		if zulu.IsServerKeyTLS(k) {
			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.logger.Fields("key", k, "err", err).Error("listener failed")
		}
	}(key, srv)
}

func (s *Server) serverAwaitErrors() error {
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

func (s *Server) serverWatchConfig() {
	for {
		select {
		case <-s.hostManager.Changed():
			s.Reload()
		case <-s.shutdown.Done():
			return
		}
	}
}

// =============================================================================
// Request Handling
// =============================================================================

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	if r.URL.Path == "/favicon.ico" {
		s.handleFavicon(w, r)
		return
	}

	if info := wellknown.NewPathInfo(r.URL.Path); info != nil && info.IsACMEChallenge() {
		if s.tlsManager != nil && s.tlsManager.Challenges != nil {
			if token, ok := info.GetACMEToken(); ok {
				if keyAuth, ok := s.tlsManager.Challenges.GetKeyAuth(token); ok {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(keyAuth))
					s.logRequest("ACME", r, start, http.StatusOK, int64(len(keyAuth)))
					return
				}
			}
		}
		http.Error(w, "Challenge not found", http.StatusNotFound)
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

		if hcfg == nil {
			if port, ok := r.Context().Value(woos.CtxPort).(string); ok && port != "" {
				if portMatch := s.hostManager.GetByPort(port); portMatch != nil {
					hcfg = portMatch
				}
			}
		}
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
		s.handleRoute(rw, r, res.Route, hcfg)
		s.logRequest(host, r, start, rw.StatusCode, rw.BytesWritten)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
	s.logRequest(host, r, start, http.StatusNotFound, 0)
}

func (s *Server) handleRoute(w http.ResponseWriter, r *http.Request, route *alaye.Route, host *alaye.Host) {
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
	var handler http.Handler = s.routeBuilder(route, host)

	if route.Wasm.Enabled.Active() {
		wm, err := s.wasmManager(&route.Wasm, routeKey)
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

func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=31536000")
	if len(operation.Favicon) > 0 {
		http.ServeContent(w, r, "favicon.ico", operation.ModTime, bytes.NewReader(operation.Favicon))
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

// =============================================================================
// Route Handler Management
// =============================================================================

func (s *Server) routeBuilder(route *alaye.Route, host *alaye.Host) *handlers.Route {
	key := route.Key()
	if it, ok := zulu.Route.Load(key); ok {
		if h, ok := it.Value.(*handlers.Route); ok {
			s.reaper.Touch(key)
			return h
		}
	}

	h := handlers.NewRoute(handlers.Config{
		Global: s.global,
		Host:   host,
		Logger: s.logger,
		IPMgr:  s.ipMgr,
	}, route)
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

// =============================================================================
// Extention and Plugin
// =============================================================================

func (s *Server) wasmManager(cfg *alaye.Wasm, key string) (*wasm.Manager, error) {
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

func (s *Server) wasmCleanup() {
	s.wasmCache.Range(func(key, value any) bool {
		if mgr, ok := value.(*wasm.Manager); ok {
			mgr.Close(context.Background())
		}
		s.wasmCache.Delete(key)
		return true
	})
}

// =============================================================================
// Middleware Chain Building
// =============================================================================

func (s *Server) chainBuild(next http.Handler, advertiseH3 bool, port string) http.Handler {
	h := memory.Middleware(next)

	if advertiseH3 {
		h = h3.AdvertiseHTTP3(port)(h)
	}

	h = s.chainBuildFirewall(h)

	if s.global.Logging.Prometheus.Enabled.Active() {
		h = observability.Prometheus(s.hostManager)(h)
	}

	h = recovery.New(s.logger)(h)
	return h
}

func (s *Server) chainBuildFirewall(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		fw := s.firewall
		s.mu.RUnlock()

		if fw != nil {
			fw.Handler(next, nil).ServeHTTP(w, r)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

func (s *Server) chainBuildRateLimiter(global *alaye.Global, ipMgr *zulu.IPManager) *ratelimit.RateLimiter {
	if global == nil {
		return nil
	}

	rlc := global.RateLimits

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

	return ratelimit.New(ratelimit.Config{
		TTL:        rlc.TTL,
		MaxEntries: rlc.MaxEntries,
		Policy:     policy,
		IPManager:  ipMgr,
	})
}

// =============================================================================
// TLS Configuration
// =============================================================================

func (s *Server) tlsBuild(next http.Handler) (*tls.Config, http.Handler) {
	if s.global == nil || s.logger == nil || s.hostManager == nil {
		return &tls.Config{}, next
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

	return tlsCfg, httpHandler
}

func (s *Server) mtlsApply(cfg *tls.Config, host *alaye.Host) {
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

func (s *Server) tlsValidate() error {
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

// =============================================================================
// Configuration Management Helpers
// =============================================================================

func (s *Server) configApplyReload(global *alaye.Global, sha string, newIPMgr *zulu.IPManager, newRateLimiter *ratelimit.RateLimiter) {
	if s.global.Logging.Level != global.Logging.Level {
		s.logger.Infof("log_level: %s → %s", s.global.Logging.Level, global.Logging.Level)
	}
	s.configSHA = sha
	s.global = global
	s.ipMgr = newIPMgr

	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
	s.rateLimiter = newRateLimiter

	if s.firewall != nil {
		s.firewall.Close()
		s.firewall = nil
	}

	if global.Security.Enabled.Active() {
		fwConfig := global.Security.Firewall
		if fwConfig.Status.Active() {
			dataDir := woos.NewFolder(global.Storage.DataDir)
			var err error
			s.firewall, err = firewall.New(firewall.Config{
				Firewall: &fwConfig, DataDir: dataDir, Logger: s.logger, IPMgr: newIPMgr,
			})
			if err != nil {
				s.logger.Fields("err", err).Error("failed to init firewall on reload")
			}
		}
	}

	if global.Security.Enabled.Active() && global.Security.InternalAuthKey != "" {
		mgr, err := security.LoadKeys(global.Security.InternalAuthKey)
		if err != nil {
			s.logger.Fields("err", err).Error("failed to reload internal auth key")
		} else {
			s.securityManager = mgr
		}
	}

	if s.tlsManager != nil {
		s.tlsManager.Close()
	}
	s.tlsManager = tlss2.NewManager(s.logger, s.hostManager, s.global)
	if s.activeTlsConfig != nil {
		s.activeTlsConfig.GetConfigForClient = s.tlsManager.GetConfigForClient
	}

	if s.clusterManager != nil {
		s.tlsManager.SetUpdateCallback(func(domain string, certPEM, keyPEM []byte) {
			if err := s.clusterManager.BroadcastCert(domain, certPEM, keyPEM); err != nil {
				s.logger.Fields("domain", domain, "err", err).Error("failed to broadcast certificate")
			}
		})
	}

	zulu.Route.Clear()
}

func (s *Server) configBuildRoute(hosts map[string]*alaye.Host) map[string]bool {
	validKeys := make(map[string]bool)
	for _, h := range hosts {
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
	return validKeys
}

func (s *Server) configComputeSHA() (string, error) {
	hasher := sha256.New()

	s.mu.RLock()
	configPath := s.configPath
	s.mu.RUnlock()

	mainData, err := os.ReadFile(configPath)
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

// =============================================================================
// Request Logging
// =============================================================================

func (s *Server) logRequest(host string, r *http.Request, start time.Time, status int, bytes int64) {
	if s.logger == nil {
		return
	}

	if s.skipLogPaths[r.URL.Path] {
		return
	}

	argsPtr := logArgsPool.Get().(*[]any)
	args := *argsPtr
	args = args[:0]

	remoteIP := r.RemoteAddr
	if s.ipMgr != nil {
		remoteIP = s.ipMgr.ClientIP(r)
	}

	args = append(args, "host", host)
	args = append(args, "path", r.URL.Path)
	args = append(args, "remote", remoteIP)
	args = append(args, "duration", time.Since(start))
	args = append(args, "proto", r.Proto)
	args = append(args, "status", status)
	args = append(args, "bytes", bytes)

	if port, ok := r.Context().Value(woos.CtxPort).(string); ok && port != "" {
		args = append(args, "port", port)
	}

	if s.global != nil && s.logUserAgentCheck(r) {
		args = append(args, "ua", zulu.Truncate(r.UserAgent(), 50))
	}

	s.logger.Fields(args...).Info(r.Method)

	*argsPtr = args
	logArgsPool.Put(argsPtr)
}

func (s *Server) logUserAgentCheck(r *http.Request) bool {
	ua := r.UserAgent()
	return strings.Contains(ua, "bot") ||
		strings.Contains(ua, "crawl") ||
		strings.Contains(ua, "spider") ||
		len(ua) > 100
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

// =============================================================================
// HTTP Redirect Helpers
// =============================================================================

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

// =============================================================================
// Reload Helpers
// =============================================================================

func (s *Server) startNewListeners(global *alaye.Global, newHosts map[string]*alaye.Host) {
	anyStreaming := anyStreamingEnabled(newHosts)

	for _, addr := range global.Bind.HTTPS {
		key := zulu.ServerKey(addr, true)
		if _, exists := s.servers[key]; !exists {
			_, port, _ := net.SplitHostPort(addr)
			srv, _, tracker := s.serverCreate(config{
				addr:        addr,
				isTLS:       true,
				tlsConfig:   s.activeTlsConfig,
				baseHandler: s.activeBaseHandler,
				acmeHandler: s.activeAcmeHandler,
				streaming:   anyStreaming,
				port:        port,
				hostManager: s.hostManager,
			})
			s.servers[key] = srv
			s.connTrackers[addr] = tracker

			h3Server, h3Key := s.serverCreateQUIC(addr, s.activeTlsConfig, s.activeBaseHandler, port)
			if h3Server != nil {
				s.h3Servers[h3Key] = h3Server
				s.serverRunQUIC(h3Server, addr)
			}

			s.serverStartAsync(key, srv)
		}
	}

	for _, addr := range global.Bind.HTTP {
		key := zulu.ServerKey(addr, false)
		if _, exists := s.servers[key]; !exists {
			_, port, _ := net.SplitHostPort(addr)
			srv, _, _ := s.serverCreate(config{
				addr:        addr,
				isTLS:       false,
				tlsConfig:   nil,
				baseHandler: s.activeBaseHandler,
				acmeHandler: s.activeAcmeHandler,
				streaming:   anyStreaming,
				port:        port,
				hostManager: s.hostManager,
			})
			s.servers[key] = srv
			s.serverStartAsync(key, srv)
		}
	}

	for _, h := range newHosts {
		for _, port := range h.Bind {
			addr := ":" + port
			isTLS := true
			if h.TLS.Mode == alaye.ModeLocalNone {
				isTLS = false
			}
			key := zulu.ServerKey(addr, isTLS)

			if _, exists := s.servers[key]; !exists {
				srv, _, tracker := s.serverCreate(config{
					addr:        addr,
					isTLS:       isTLS,
					tlsConfig:   s.activeTlsConfig,
					baseHandler: s.activeBaseHandler,
					acmeHandler: s.activeAcmeHandler,
					streaming:   anyStreaming,
					port:        port,
					hostManager: s.hostManager,
				})
				s.servers[key] = srv

				if isTLS {
					s.connTrackers[addr] = tracker
					h3Server, h3Key := s.serverCreateQUIC(addr, s.activeTlsConfig, s.activeBaseHandler, port)
					if h3Server != nil {
						s.h3Servers[h3Key] = h3Server
						s.serverRunQUIC(h3Server, addr)
					}
				}
				s.serverStartAsync(key, srv)
			}
		}
	}
}
