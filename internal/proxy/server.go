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

	// 1. Initialize IP Middleware
	s.ipMiddleware = NewIPMiddleware(s.global.TrustedProxies)

	// 2. Parse Bind Addresses
	addrs := parseBind(s.global.Bind)
	if len(addrs) == 0 {
		return errors.Newf("no bind addresses configured (bind=%q)", s.global.Bind)
	}

	// 3. Configure Timeouts
	// Ensure struct exists (parser might leave it nil)
	if s.global.Timeouts == nil {
		s.global.Timeouts = &config.TimeoutConfig{}
	}
	readTimeout := parseDuration(s.global.Timeouts.Read, config.DefaultReadTimeout)
	writeTimeout := parseDuration(s.global.Timeouts.Write, config.DefaultWriteTimeout)
	idleTimeout := parseDuration(s.global.Timeouts.Idle, config.DefaultIdleTimeout)
	readHeaderTimeout := parseDuration(s.global.Timeouts.ReadHeader, config.DefaultReadHeaderTimeout)

	// 4. Setup Handlers & TLS
	baseHandler := http.HandlerFunc(s.handleRequest)

	tlsCfg, httpHandler, err := s.buildTLS(baseHandler)
	if err != nil {
		s.logger.Fields("err", err.Error()).Warn("TLS setup failed; HTTPS listeners may not start")
		httpHandler = baseHandler
		tlsCfg = nil
	}

	// 5. Create Servers
	for _, addr := range addrs {
		isTLS := isHTTPSBind(addr)

		var handler http.Handler
		if isTLS {
			// HTTPS: IP Middleware -> Router
			handler = s.ipMiddleware.Handler(baseHandler)
		} else {
			// HTTP: IP Middleware -> ACME HTTP-01 (if enabled) -> Router
			// We wrap the httpHandler (which contains the ACME check) with IP middleware
			// so the logger inside ACME/Router sees the real IP.
			handler = s.ipMiddleware.Handler(httpHandler)
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

	// 6. Start Listeners
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

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := normalizeHost(r.Host)

	hcfg := s.hostManager.Get(host)
	if hcfg == nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	// SECURITY: Body Limits
	maxBody := int64(config.DefaultMaxBodySize)
	if hcfg.Limits != nil && hcfg.Limits.MaxBodySize > 0 {
		maxBody = hcfg.Limits.MaxBodySize
	}

	if r.ContentLength > maxBody {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	// Routing
	for i := range hcfg.Routes {
		route := hcfg.Routes[i]
		if pathMatch(r.URL.Path, route.Path) {
			s.handleRoute(w, r, &route)
			s.logRequest(host, r, start)
			return
		}
	}

	// Static Web
	if hcfg.Web != nil {
		s.handleWeb(w, r, hcfg.Web)
		s.logRequest(host, r, start)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
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
	if v, loaded := routeCache.LoadOrStore(key, h); loaded {
		return v.(*routeHandler)
	}
	return h
}

func (s *Server) buildTLS(next http.Handler) (*tls.Config, http.Handler, error) {
	m := &tlsManager{
		logger:      NewTLSLogger(s.logger),
		hostManager: s.hostManager,
		global:      s.global,
		localCache:  make(map[string]*tls.Certificate),
	}

	issuer, httpHandler, err := m.ensureCertMagic(next)
	if err != nil {
		s.logger.Fields("err", err.Error()).Warn("certmagic not enabled; using HTTP handler without ACME")
		httpHandler = next
		issuer = nil
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
				if issuer == nil {
					return nil, errors.Newf("letsencrypt not enabled globally (host %q)", sni)
				}
				cmTLS := m.cmCfg.TLSConfig()
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

func (s *Server) logRequest(host string, r *http.Request, start time.Time) {
	s.logger.Fields(
		"host", host,
		"method", r.Method,
		"path", r.URL.Path,
		"remote", r.RemoteAddr, // Will be real IP via Middleware
		"ua", r.UserAgent(),
		"duration", time.Since(start),
	).Info("request")
}
