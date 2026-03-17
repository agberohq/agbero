package handlers

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/middleware/h3"
	"github.com/agberohq/agbero/internal/middleware/memory"
	"github.com/agberohq/agbero/internal/middleware/observability"
	"github.com/agberohq/agbero/internal/middleware/recovery"
	"github.com/agberohq/agbero/internal/operation"
	"github.com/agberohq/agbero/internal/pkg/wellknown"
	"github.com/olekukonko/mappo"
)

// chainBuild assembles the HTTP middleware stack with optional HTTP/3 advertisement support.
// It composes memory, firewall, Prometheus metrics, and panic recovery middleware around the base handler.
func (m *Manager) chainBuild(next http.Handler, advertiseH3 bool, port string) http.Handler {
	h := memory.Middleware(next)
	if advertiseH3 {
		h = h3.AdvertiseHTTP3(port)(h)
	}
	h = m.chainBuildFirewall(h)
	if m.cfg.Global.Logging.Prometheus.Enabled.Active() {
		h = observability.Prometheus(m.cfg.HostManager)(h)
	}
	h = recovery.New(m.cfg.Resource.Logger)(h)
	return h
}

// chainBuildFirewall conditionally wraps the handler with firewall rule enforcement.
// The firewall handler is constructed once at chain build time, not per request.
func (m *Manager) chainBuildFirewall(next http.Handler) http.Handler {
	fw := m.firewall
	if fw == nil {
		return next
	}
	fwHandler := fw.Handler(next, nil)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fwHandler.ServeHTTP(w, r)
	})
}

// handleRequest is the primary HTTP request dispatcher that resolves host configuration and routes incoming traffic.
// It handles special paths like favicon and ACME challenges, validates request size, and delegates to the appropriate router.
func (m *Manager) handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	if r.URL.Path == "/favicon.ico" {
		m.handleFavicon(w, r)
		return
	}

	if info := wellknown.NewPathInfo(r.URL.Path); info != nil {
		if info.IsACMEChallenge() {
			if m.cfg.TLSManager != nil && m.cfg.TLSManager.Challenges != nil {
				if token, ok := info.GetACMEToken(); ok {
					if keyAuth, ok := m.cfg.TLSManager.Challenges.GetKeyAuth(token); ok {
						w.Header().Set("Content-Type", "text/plain")
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(keyAuth))
						m.logRequest(r.Host, r, start, http.StatusOK, int64(len(keyAuth)))
						return
					}
				}
			}
			http.Error(w, "Challenge not found", http.StatusNotFound)
			return
		}

		if routeKey, ok := info.GetWebhookRouteKey(); ok {
			if m.cfg.CookManager != nil {
				m.cfg.CookManager.HandleWebhook(w, r, routeKey)
				m.logRequest("Webhook", r, start, http.StatusAccepted, 0)
			} else {
				http.Error(w, "Git manager disabled", http.StatusServiceUnavailable)
				m.logRequest("Webhook", r, start, http.StatusServiceUnavailable, 0)
			}
			return
		}
	}

	var host string
	var hcfg *alaye.Host

	lctx, hasLctx := r.Context().Value(woos.ListenerCtxKey).(woos.ListenerCtx)

	if hasLctx && lctx.Owner != nil {
		hcfg = lctx.Owner
		if len(hcfg.Domains) > 0 {
			host = hcfg.Domains[0]
		} else {
			host = woos.PrivateBindingHost
		}
	} else {
		host = zulu.NormalizeHost(r.Host)
		hcfg = m.cfg.HostManager.Get(host)

		if hcfg == nil && hasLctx && lctx.Port != "" {
			if portMatch := m.cfg.HostManager.GetByPort(lctx.Port); portMatch != nil {
				hcfg = portMatch
			}
		}
	}

	if hcfg == nil {
		http.Error(w, "Hosting not found", http.StatusNotFound)
		m.logRequest(host, r, start, http.StatusNotFound, 0)
		return
	}

	maxBody := int64(alaye.DefaultMaxBodySize)
	if hcfg.Limits.MaxBodySize > 0 {
		maxBody = hcfg.Limits.MaxBodySize
	}

	if r.ContentLength > maxBody {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		m.logRequest(host, r, start, http.StatusRequestEntityTooLarge, 0)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	var routerName string
	if len(hcfg.Domains) > 0 {
		routerName = hcfg.Domains[0]
	} else {
		routerName = host
	}

	router := m.cfg.HostManager.GetRouter(routerName)
	if router == nil && routerName != host {
		router = m.cfg.HostManager.GetRouter(host)
	}

	if router == nil {
		http.Error(w, "Hosting configuration found but router unavailable", http.StatusNotFound)
		m.logRequest(host, r, start, http.StatusNotFound, 0)
		return
	}

	res := router.Find(r.URL.Path)
	if res.Route != nil {
		rw := &zulu.ResponseWriter{
			ResponseWriter: w,
			StatusCode:     200,
		}

		m.handleRoute(rw, r, res.Route, hcfg)
		m.logRequest(host, r, start, rw.StatusCode, rw.BytesWritten)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
	m.logRequest(host, r, start, http.StatusNotFound, 0)
}

// handleRoute prepares the request context and applies route-specific middleware before delegation.
// It handles path prefix stripping, optional WASM middleware injection, rate limiting, and invokes the route handler.
func (m *Manager) handleRoute(w http.ResponseWriter, r *http.Request, route *alaye.Route, host *alaye.Host) {
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
	var handler http.Handler = m.routeBuilder(route, host)

	if route.Wasm.Enabled.Active() {
		wm, err := m.wasmManager(&route.Wasm, routeKey)
		if err != nil {
			m.cfg.Resource.Logger.Fields("err", err, "module", route.Wasm.Module).Error("wasm: failed to load middleware")
			http.Error(w, "Internal Server Error (WASM)", http.StatusInternalServerError)
			return
		}
		handler = wm.Handler(handler)
	}

	if m.rateLimiter != nil {
		if !route.RateLimit.IgnoreGlobal {
			handler = m.rateLimiter.Handler(handler)
		}
	}

	handler.ServeHTTP(w, reqOut)
}

// routeBuilder constructs or retrieves a cached Route handler for the given route configuration.
// It manages cache lifecycle with touch timestamps and ensures efficient reuse of route handler instances.
func (m *Manager) routeBuilder(route *alaye.Route, host *alaye.Host) *Route {
	key := route.Key()
	if it, ok := m.cfg.Resource.RouteCache.Load(key); ok {
		if h, ok := it.Value.(*Route); ok {
			now := time.Now().Unix()
			if now-h.lastTouch.Load() > 10 {
				h.lastTouch.Store(now)
				if m.cfg.Resource.Reaper != nil {
					m.cfg.Resource.Reaper.Touch(key)
				}
			}
			return h
		}
	}

	h := NewRoute(resource.Proxy{
		Global:      m.cfg.Global,
		Host:        host,
		IPMgr:       m.cfg.IPMgr,
		CookMgr:     m.cfg.CookManager,
		Resource:    m.cfg.Resource,
		SharedState: m.cfg.SharedState,
	}, route)

	newItem := &mappo.Item{Value: h}

	if it, loaded := m.cfg.Resource.RouteCache.LoadOrStore(key, newItem); loaded {
		_ = h.Close()
		if existing, ok := it.Value.(*Route); ok {
			now := time.Now().Unix()
			if now-existing.lastTouch.Load() > 10 {
				existing.lastTouch.Store(now)
				if m.cfg.Resource.Reaper != nil {
					m.cfg.Resource.Reaper.Touch(key)
				}
			}
			return existing
		}
	}

	h.lastTouch.Store(time.Now().Unix())
	if m.cfg.Resource.Reaper != nil {
		m.cfg.Resource.Reaper.Touch(key)
	}
	return h
}

// handleFavicon serves the embedded favicon.ico with long-term caching headers for browser efficiency.
// It returns a 404 status if no favicon data is available in the operation package.
func (m *Manager) handleFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=31536000")
	if len(operation.Favicon) > 0 {
		http.ServeContent(w, r, "favicon.ico", zulu.ModTime, bytes.NewReader(operation.Favicon))
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

// redirectToHTTPS constructs and issues a permanent redirect to the HTTPS equivalent of the current request.
// It respects host-specific bind ports and falls back to global HTTPS configuration for the target URL.
func (m *Manager) redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	if lctx, ok := r.Context().Value(woos.ListenerCtxKey).(woos.ListenerCtx); ok && lctx.Owner != nil {
		for _, bindPort := range lctx.Owner.Bind {
			if bindPort != "" {
				target := fmt.Sprintf("https://%s:%s%s", host, bindPort, r.URL.RequestURI())
				http.Redirect(w, r, target, http.StatusMovedPermanently)
				return
			}
		}
	}

	targetPort := woos.DefaultHTTPSPortInt
	if len(m.cfg.Global.Bind.HTTPS) > 0 {
		_, port, err := net.SplitHostPort(m.cfg.Global.Bind.HTTPS[0])
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

// logRequest records structured access log entries for HTTP requests with timing and metadata.
// It pools argument slices for efficiency and includes host, path, duration, status, and optional bot detection data.
func (m *Manager) logRequest(host string, r *http.Request, start time.Time, status int, bytes int64) {
	if m.cfg.Resource.Logger == nil {
		return
	}

	if m.skipLogPaths[r.URL.Path] {
		return
	}

	argsPtr := m.logArgsPool.Get().(*[]any)
	args := *argsPtr
	args = args[:0]

	remoteIP := r.RemoteAddr
	if m.cfg.IPMgr != nil {
		remoteIP = m.cfg.IPMgr.ClientIP(r)
	}

	args = append(args, "host", host)
	args = append(args, "path", r.URL.Path)
	args = append(args, "remote", remoteIP)
	args = append(args, "duration", time.Since(start))
	args = append(args, "proto", r.Proto)
	args = append(args, "status", status)
	args = append(args, "bytes", bytes)

	if lctx, ok := r.Context().Value(woos.ListenerCtxKey).(woos.ListenerCtx); ok && lctx.Port != "" {
		args = append(args, "port", lctx.Port)
	}

	if m.cfg.Global != nil {
		ua := r.UserAgent()
		if m.cfg.Global.Logging.Truncate.Active() {
			args = append(args, "ua", zulu.Truncate(ua, 50))
		} else {
			args = append(args, "ua", zulu.Truncate(ua, 50))
		}
		if m.cfg.Global.Logging.BotChecker.Active() {
			args = append(args, "bot", m.botChecker.IsBot(ua))
		}
	}

	m.cfg.Resource.Logger.Fields(args...).Info(r.Method)
	*argsPtr = args
	m.logArgsPool.Put(argsPtr)
}
