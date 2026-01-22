// internal/proxy/server.go
package proxy

import (
	"context"
	"crypto/tls"
	"net/http"
	"strings"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/config"
	"git.imaxinacion.net/aibox/agbero/internal/discovery"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/ll"
)

type Server struct {
	hostManager *discovery.Host
	global      *config.GlobalConfig

	mu      sync.RWMutex
	servers map[string]*http.Server

	logger       *ll.Logger
	ipMiddleware *IPMiddleware
	rateLimiter  *RateLimiter
}

func NewServer(opts ...Option) *Server {
	s := &Server{
		servers: make(map[string]*http.Server),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Server) Start(ctx context.Context) error {
	if s.hostManager == nil {
		return errors.New("host manager is required")
	}
	if s.global == nil {
		return errors.New("global config is required")
	}
	if s.logger == nil {
		s.logger = ll.New(config.Name).Enable()
	}

	// Apply defaults (timeouts, rate limits, etc.) if not set in config.
	// This is where you guarantee "all values come from config"
	// while still having safe defaults when missing.
	config.ApplyDefaults(s.global)

	// Middleware: Real client IP (trusted proxies)
	s.ipMiddleware = NewIPMiddleware(s.global.TrustedProxies)

	// Middleware: Rate limiting (config driven, bounded, TTL)
	s.rateLimiter = s.buildRateLimiterFromConfig()

	addrs := parseBind(s.global.Bind)
	if len(addrs) == 0 {
		return errors.Newf("no bind addresses configured (bind=%q)", s.global.Bind)
	}

	// Timeouts (strings) -> time.Duration (with defaults already applied)
	readTimeout := parseDuration(s.global.Timeouts.Read, config.DefaultReadTimeout)
	writeTimeout := parseDuration(s.global.Timeouts.Write, config.DefaultWriteTimeout)
	idleTimeout := parseDuration(s.global.Timeouts.Idle, config.DefaultIdleTimeout)
	readHeaderTimeout := parseDuration(s.global.Timeouts.ReadHeader, config.DefaultReadHeaderTimeout)

	baseHandler := http.HandlerFunc(s.handleRequest)

	// TLS config and HTTP handler wrapper (HTTP-01 challenge support)
	tlsCfg, httpHandler, err := s.buildTLS(baseHandler)
	if err != nil {
		s.logger.Fields("err", err.Error()).Warn("TLS setup failed; HTTPS listeners may not start")
		httpHandler = baseHandler
		tlsCfg = nil
	}

	// Create servers from bind config.
	for _, addr := range addrs {
		isTLS := isHTTPSBind(addr)

		// Chain: IP -> RateLimit -> (HTTP-01 wrapper if HTTP) -> Router
		var handler http.Handler
		if isTLS {
			handler = s.ipMiddleware.Handler(s.rateLimiter.Handler(baseHandler))
		} else {
			handler = s.ipMiddleware.Handler(s.rateLimiter.Handler(httpHandler))
		}

		srv := &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
			ReadHeaderTimeout: readHeaderTimeout,
			MaxHeaderBytes:    config.DefaultMaxHeaderBytes,
		}

		if isTLS && tlsCfg != nil {
			srv.TLSConfig = tlsCfg
		}

		key := serverKey(addr, isTLS)

		s.mu.Lock()
		s.servers[key] = srv
		s.mu.Unlock()
	}

	// Start each server.
	errCh := make(chan error, len(s.servers))

	s.mu.RLock()
	for key, srv := range s.servers {
		key := key
		srv := srv

		go func() {
			s.logger.Fields("bind", srv.Addr, "key", key).Info("listener starting")

			var err error
			if isServerKeyTLS(key) {
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

	return s.waitOrShutdown(ctx, errCh)
}

func (s *Server) waitOrShutdown(ctx context.Context, errCh <-chan error) error {
	for {
		select {
		case <-ctx.Done():
			return s.shutdown()
		case err := <-errCh:
			if err != nil {
				_ = s.shutdown()
				return err
			}
		}
	}
}

func (s *Server) shutdown() error {
	// stop limiter sweeper (optional but clean)
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

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
	return firstErr
}

func (s *Server) buildRateLimiterFromConfig() *RateLimiter {
	rlc := s.global.RateLimits

	ttl := parseDuration(rlc.TTL, 30*time.Minute)
	maxEntries := rlc.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 100_000
	}

	gr, gw, gb, gok := config.ParseRatePolicy(rlc.Global)
	ar, aw, ab, aok := config.ParseRatePolicy(rlc.Auth)

	globalPolicy := RatePolicy{Requests: gr, Window: gw, Burst: gb}
	authPolicy := RatePolicy{Requests: ar, Window: aw, Burst: ab}

	authPrefixes := rlc.AuthPrefixes
	if len(authPrefixes) == 0 {
		authPrefixes = []string{"/login", "/otp", "/auth"}
	}

	policy := func(r *http.Request) (bucket string, pol RatePolicy, ok bool) {
		p := r.URL.Path

		if strings.HasPrefix(p, "/.well-known/acme-challenge/") {
			return "acme", RatePolicy{}, false
		}

		for _, pref := range authPrefixes {
			if pref != "" && strings.HasPrefix(p, pref) {
				if aok {
					return "auth", authPolicy, true
				}
				return "auth_disabled", RatePolicy{}, false
			}
		}

		if gok {
			return "global", globalPolicy, true
		}
		return "global_disabled", RatePolicy{}, false
	}

	return NewRateLimiter(ttl, maxEntries, policy)
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	host := normalizeHost(r.Host)

	hcfg := s.hostManager.Get(host)
	if hcfg == nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	// Body limit per host
	maxBody := int64(config.DefaultMaxBodySize)
	if hcfg.Limits != nil && hcfg.Limits.MaxBodySize > 0 {
		maxBody = hcfg.Limits.MaxBodySize
	}

	if r.ContentLength > maxBody {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	// Routes first
	for i := range hcfg.Routes {
		route := hcfg.Routes[i]
		if pathMatch(r.URL.Path, route.Path) {
			s.handleRoute(w, r, &route)
			s.logRequest(host, r, start)
			return
		}
	}

	// Static web
	if hcfg.Web != nil {
		s.handleWeb(w, r, hcfg.Web)
		s.logRequest(host, r, start)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

func (s *Server) logRequest(host string, r *http.Request, start time.Time) {
	s.logger.Fields(
		"host", host,
		"method", r.Method,
		"path", r.URL.Path,
		"remote", ClientIP(r),
		"ua", r.UserAgent(),
		"duration", time.Since(start),
	).Info("request")
}

func (s *Server) handleRoute(w http.ResponseWriter, r *http.Request, route *config.Route) {
	originalPath := r.URL.Path
	originalRawPath := r.URL.RawPath

	if len(route.StripPrefixes) > 0 {
		for _, prefix := range route.StripPrefixes {
			if prefix == "" {
				continue
			}
			if strings.HasPrefix(r.URL.Path, prefix) {
				r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
				if r.URL.RawPath != "" {
					r.URL.RawPath = strings.TrimPrefix(r.URL.RawPath, prefix)
				}
				if r.URL.Path == "" {
					r.URL.Path = "/"
				}
				break
			}
		}
	}

	h := s.getOrBuildRouteHandler(route)
	h.ServeHTTP(w, r)

	r.URL.Path = originalPath
	r.URL.RawPath = originalRawPath
}

func (s *Server) getOrBuildRouteHandler(route *config.Route) *routeHandler {
	key := routeKey(route)

	if v, ok := routeCache.Load(key); ok {
		return v.(*routeHandler)
	}

	h := newRouteHandler(route)

	// Avoid double-build races
	if v, loaded := routeCache.LoadOrStore(key, h); loaded {
		return v.(*routeHandler)
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

	m := &tlsManager{
		logger:      NewTLSLogger(s.logger),
		hostManager: s.hostManager,
		global:      s.global,
		localCache:  make(map[string]*tls.Certificate),
	}

	// Configure certmagic (prod+staging) and get HTTP-01 handler wrapper
	httpHandler, err := m.ensureCertMagic(next)
	if err != nil {
		// LE not enabled globally; still allow local cert mode to work.
		s.logger.Fields("err", err.Error()).Warn("certmagic not enabled; using HTTP handler without ACME")
		httpHandler = next
		// NOTE: We'll still build tlsCfg, but LetsEncrypt mode will fail at handshake.
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if chi == nil || chi.ServerName == "" {
				return nil, errors.New("missing SNI")
			}

			sni := normalizeSubject(chi.ServerName)

			hcfg := s.hostManager.Get(sni)
			if hcfg == nil {
				return nil, errors.Newf("unknown host %q", sni)
			}

			// Default TLS behavior if tls block missing.
			mode := config.ModeLetsEncrypt
			if hcfg.TLS != nil && hcfg.TLS.Mode != "" {
				mode = hcfg.TLS.Mode
			}

			switch mode {
			case config.ModeLocalNone:
				return nil, errors.Newf("tls disabled for host %q", sni)

			case config.ModeLocalCert:
				if hcfg.TLS == nil {
					return nil, errors.Newf("tls=local requires tls block for host %q", sni)
				}
				return m.getLocalCertificate(hcfg.TLS.Local, sni)

			case config.ModeLetsEncrypt:
				cm := m.cmForHost(hcfg)
				if cm == nil {
					return nil, errors.Newf("letsencrypt not enabled globally (host %q)", sni)
				}

				cmTLS := cm.TLSConfig()
				chi2 := *chi
				chi2.ServerName = sni
				return cmTLS.GetCertificate(&chi2)

			default:
				return nil, errors.Newf("unknown tls mode %q for host %q", mode, sni)
			}
		},
	}

	return tlsCfg, httpHandler, nil
}
