package handlers

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/handlers/xtcp"
	"github.com/agberohq/agbero/internal/handlers/xudp"
	"github.com/agberohq/agbero/internal/hub/cook"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/hub/orchestrator"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/hub/tlss"
	"github.com/agberohq/agbero/internal/middleware/firewall"
	"github.com/agberohq/agbero/internal/middleware/ratelimit"
	"github.com/agberohq/agbero/internal/middleware/wasm"
	"github.com/agberohq/agbero/internal/pkg/bot"
	"github.com/olekukonko/errors"
	"github.com/quic-go/quic-go/http3"
)

type ManagerConfig struct {
	Global      *alaye.Global
	HostManager *discovery.Host
	Resource    *resource.Resource
	IPMgr       *zulu.IPManager
	CookManager *cook.Manager
	TLSManager  *tlss.Manager
	SharedState woos.SharedState
	OrchManager *orchestrator.Manager
}

type Manager struct {
	cfg          ManagerConfig
	wasmCache    sync.Map
	skipLogPaths map[string]bool

	baseHandler http.Handler
	acmeHandler http.Handler
	tlsConfig   *tls.Config

	firewall    *firewall.Engine
	rateLimiter *ratelimit.RateLimiter

	logArgsPool sync.Pool
	botChecker  *bot.Checker
}

type llWriter struct {
	logger interface{ Error(args ...any) }
}

func (w *llWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	w.logger.Error("source", "std_http", "msg", msg)
	return len(p), nil
}

func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Global == nil {
		return nil, errors.New("global config required")
	}
	if cfg.HostManager == nil {
		return nil, errors.New("host manager required")
	}
	if cfg.Resource == nil {
		return nil, errors.New("resource manager required")
	}
	m := &Manager{
		cfg:          cfg,
		skipLogPaths: make(map[string]bool),
		logArgsPool: sync.Pool{
			New: func() any {
				s := make([]any, 0, 16)
				return &s
			},
		},
		botChecker: bot.NewChecker(),
	}
	if cfg.Global.Logging.Enabled.Active() && len(cfg.Global.Logging.Skip) > 0 {
		for _, p := range cfg.Global.Logging.Skip {
			m.skipLogPaths[p] = true
		}
	}
	m.rateLimiter = buildGlobalRateLimiter(cfg.Global, cfg.IPMgr, cfg.SharedState)
	if cfg.Global.Security.Enabled.Active() {
		fwConfig := cfg.Global.Security.Firewall
		if fwConfig.Status.Active() {
			fw, err := firewall.New(firewall.Config{
				Firewall:       &fwConfig,
				TrustedProxies: cfg.Global.Security.TrustedProxies,
				DataDir:        cfg.Global.Storage.DataDir,
				Logger:         cfg.Resource.Logger,
				IPMgr:          cfg.IPMgr,
				SharedState:    cfg.SharedState,
				BotChecker:     m.botChecker,
			})
			if err != nil {
				return nil, errors.Newf("firewall init: %w", err)
			}
			m.firewall = fw
		}
	}
	m.baseHandler = http.HandlerFunc(m.handleRequest)
	m.acmeHandler = m.baseHandler
	if len(cfg.Global.Bind.HTTPS) > 0 && cfg.Global.Bind.Redirect.Active() {
		m.acmeHandler = http.HandlerFunc(m.redirectToHTTPS)
	}
	if cfg.TLSManager != nil {
		handler, err := cfg.TLSManager.EnsureCertMagic(m.acmeHandler)
		if err == nil {
			m.acmeHandler = handler
		} else {
			cfg.Resource.Logger.Fields("err", err.Error()).Warn("certmagic not enabled; using HTTP handler without ACME")
		}
		m.tlsConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
			NextProtos:         []string{def.AlpnTls, def.AlpnH3, def.AlpnH2, def.AlpnH11},
			GetConfigForClient: cfg.TLSManager.GetConfigForClient,
		}
	}
	return m, nil
}

func (m *Manager) CloseFirewall() {
	if m != nil && m.firewall != nil {
		_ = m.firewall.Close()
		m.firewall = nil
	}
}

func (m *Manager) Close() {
	if m.firewall != nil {
		_ = m.firewall.Close()
	}
	if m.rateLimiter != nil {
		m.rateLimiter.Close()
	}
	m.wasmCleanup()
}

func (m *Manager) Firewall() *firewall.Engine {
	return m.firewall
}

func (m *Manager) BuildListeners() []Listener {
	var listeners []Listener
	hosts, _ := m.cfg.HostManager.LoadAll()
	usedPorts := make(map[string]bool)

	for _, h := range hosts {
		for i := range h.Routes {
			_ = m.routeBuilder(&h.Routes[i], h)
		}
	}

	for _, addr := range m.cfg.Global.Bind.HTTP {
		if !strings.Contains(addr, ":") {
			addr = ":" + addr
		}
		_, port, _ := net.SplitHostPort(addr)
		usedPorts[port] = true
		listeners = append(listeners, m.createHTTPListener(addr, port, false))
	}

	for _, addr := range m.cfg.Global.Bind.HTTPS {
		if !strings.Contains(addr, ":") {
			addr = ":" + addr
		}
		_, port, _ := net.SplitHostPort(addr)
		usedPorts[port] = true
		listeners = append(listeners, m.createHTTPListener(addr, port, true))
		if h3 := m.createH3Listener(addr, port); h3 != nil {
			listeners = append(listeners, h3)
		}
	}

	for _, h := range hosts {
		for _, port := range h.Bind {
			if usedPorts[port] {
				continue
			}
			usedPorts[port] = true
			addr := port
			if !strings.Contains(port, ":") {
				addr = ":" + port
			}
			isTLS := h.TLS.Mode != def.ModeLocalNone
			listeners = append(listeners, m.createHTTPListener(addr, port, isTLS))
			if isTLS {
				if h3 := m.createH3Listener(addr, port); h3 != nil {
					listeners = append(listeners, h3)
				}
			}
		}
	}

	tcpGroups := groupTCPRoutesByListen(hosts)
	// ll.Output("udp groups: %v", tcpGroups)

	for listen, routes := range tcpGroups {
		tp := xtcp.NewProxy(m.cfg.Resource, listen)
		var maxC int64
		for _, r := range routes {
			pattern := r.SNI
			if pattern == "" {
				pattern = "*"
			}
			tp.AddRoute(pattern, r)
			if r.MaxConnections > maxC {
				maxC = r.MaxConnections
			}
		}
		tp.MaxConns = maxC
		listeners = append(listeners, &TCPListener{Proxy: tp})
	}

	udpGroups := groupUDPRoutesByListen(hosts)
	// ll.Output("udp groups: %v", udpGroups)

	for listen, routes := range udpGroups {
		up := xudp.NewProxy(m.cfg.Resource, listen)
		var maxS int64
		var sessionTTL expect.Duration
		for _, r := range routes {
			up.AddRoute(r.Name, r)
			if r.MaxSessions > maxS {
				maxS = r.MaxSessions
			}
			if r.SessionTTL > sessionTTL {
				sessionTTL = r.SessionTTL
			}
		}
		up.MaxSess = maxS
		if sessionTTL > 0 {
			up.SetSessionTTL(sessionTTL.StdDuration())
		}
		listeners = append(listeners, &UDPListener{Proxy: up})
	}

	return listeners
}

func (m *Manager) createHTTPListener(addr, port string, isTLS bool) Listener {
	var handler http.Handler
	if isTLS {
		handler = m.chainBuild(m.baseHandler, true, port)
	} else {
		handler = m.chainBuild(m.acmeHandler, false, "")
	}

	owner := m.cfg.HostManager.GetByPort(port)
	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lctx := woos.ListenerCtx{Port: port, Owner: owner}
		handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), woos.ListenerCtxKey, lctx)))
	})

	tracker := NewConnTracker()
	srv := &http.Server{
		Addr:              addr,
		Handler:           wrappedHandler,
		ReadTimeout:       m.cfg.Global.Timeouts.Read.StdDuration(),
		WriteTimeout:      m.cfg.Global.Timeouts.Write.StdDuration(),
		IdleTimeout:       m.cfg.Global.Timeouts.Idle.StdDuration(),
		ReadHeaderTimeout: m.cfg.Global.Timeouts.ReadHeader.StdDuration(),
		MaxHeaderBytes:    m.cfg.Global.General.MaxHeaderBytes,
		ErrorLog:          log.New(&llWriter{logger: m.cfg.Resource.Logger}, "", 0),
		ConnState:         tracker.Track,
	}

	if isTLS && m.tlsConfig != nil {
		localCfg := m.tlsConfig.Clone()
		localCfg.GetConfigForClient = nil
		localCfg.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if chi.ServerName != "" {
				if cert, err := m.cfg.TLSManager.GetCertificate(chi); err == nil {
					return cert, nil
				}
			}
			if owner := m.cfg.HostManager.GetByPort(port); owner != nil && len(owner.Domains) > 0 {
				fallbackChi := *chi
				fallbackChi.ServerName = owner.Domains[0]
				if cert, err := m.cfg.TLSManager.GetCertificate(&fallbackChi); err == nil {
					return cert, nil
				}
			}
			return nil, errors.New("no certificate found")
		}
		srv.TLSConfig = localCfg
	}

	return &HTTPListener{Srv: srv, Tracker: tracker, IsTLS: isTLS}
}

func (m *Manager) createH3Listener(addr, port string) Listener {
	if m.tlsConfig == nil {
		return nil
	}
	handler := m.chainBuild(m.baseHandler, false, "")
	owner := m.cfg.HostManager.GetByPort(port)
	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lctx := woos.ListenerCtx{Port: port, Owner: owner}
		handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), woos.ListenerCtxKey, lctx)))
	})
	serverTLSCfg := m.tlsConfig.Clone()
	serverTLSCfg.GetConfigForClient = nil
	serverTLSCfg.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if chi.ServerName != "" {
			if cert, err := m.cfg.TLSManager.GetCertificate(chi); err == nil {
				return cert, nil
			}
		}
		if owner := m.cfg.HostManager.GetByPort(port); owner != nil && len(owner.Domains) > 0 {
			fallbackChi := *chi
			fallbackChi.ServerName = owner.Domains[0]
			if cert, err := m.cfg.TLSManager.GetCertificate(&fallbackChi); err == nil {
				return cert, nil
			}
		}
		return nil, errors.New("no certificate found")
	}
	srv := &http3.Server{
		Addr:      addr,
		Handler:   wrappedHandler,
		TLSConfig: serverTLSCfg,
	}
	return &H3Listener{Srv: srv}
}

func (m *Manager) wasmManager(cfg *alaye.Wasm, key string) (*wasm.Manager, error) {
	if v, ok := m.wasmCache.Load(key); ok {
		return v.(*wasm.Manager), nil
	}
	mgr, err := wasm.NewManager(context.Background(), m.cfg.Resource.Logger, cfg)
	if err != nil {
		return nil, err
	}
	if actual, loaded := m.wasmCache.LoadOrStore(key, mgr); loaded {
		mgr.Close(context.Background())
		return actual.(*wasm.Manager), nil
	}
	return mgr, nil
}

func (m *Manager) wasmCleanup() {
	m.wasmCache.Range(func(key, value any) bool {
		if mgr, ok := value.(*wasm.Manager); ok {
			mgr.Close(context.Background())
		}
		m.wasmCache.Delete(key)
		return true
	})
}

func groupTCPRoutesByListen(hosts map[string]*alaye.Host) map[string][]alaye.Proxy {
	tcpGroups := make(map[string][]alaye.Proxy)
	for _, host := range hosts {
		for i := range host.Proxies {
			p := host.Proxies[i]
			if !p.IsUDP() {
				tcpGroups[p.Listen] = append(tcpGroups[p.Listen], p)
			}
		}
	}
	return tcpGroups
}

func groupUDPRoutesByListen(hosts map[string]*alaye.Host) map[string][]alaye.Proxy {
	udpGroups := make(map[string][]alaye.Proxy)
	for _, host := range hosts {
		for i := range host.Proxies {
			p := host.Proxies[i]
			if p.IsUDP() {
				udpGroups[p.Listen] = append(udpGroups[p.Listen], p)
			}
		}
	}
	return udpGroups
}

func buildGlobalRateLimiter(global *alaye.Global, ipMgr *zulu.IPManager, sharedState woos.SharedState) *ratelimit.RateLimiter {
	if global == nil || !global.RateLimits.Enabled.Active() || len(global.RateLimits.Rules) == 0 {
		return nil
	}
	rlc := global.RateLimits
	policy := func(r *http.Request) (bucket string, pol ratelimit.RatePolicy, ok bool) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/.well-known/acme-challenge/") {
			return def.BucketACME, ratelimit.RatePolicy{}, false
		}
		for _, rule := range rlc.Rules {
			if len(rule.Methods) > 0 {
				methodMatch := false
				for _, m := range rule.Methods {
					if strings.EqualFold(m, r.Method) {
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
				Window:   rule.Window.StdDuration(),
				Burst:    rule.Burst,
				KeySpec:  rule.Key,
			}, true
		}
		return "", ratelimit.RatePolicy{}, false
	}
	return ratelimit.New(ratelimit.Config{
		TTL:         rlc.TTL.StdDuration(),
		MaxEntries:  rlc.MaxEntries,
		Policy:      policy,
		IPManager:   ipMgr,
		SharedState: sharedState,
	})
}
