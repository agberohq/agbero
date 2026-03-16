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

func (m *Manager) chainBuildFirewall(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fw := m.firewall
		if fw != nil {
			fw.Handler(next, nil).ServeHTTP(w, r)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

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

	if owner, ok := r.Context().Value(woos.OwnerKey).(*alaye.Host); ok && owner != nil {
		hcfg = owner
		if len(hcfg.Domains) > 0 {
			host = hcfg.Domains[0]
		} else {
			host = woos.PrivateBindingHost
		}
	} else {
		host = zulu.NormalizeHost(r.Host)
		hcfg = m.cfg.HostManager.Get(host)

		if hcfg == nil {
			if port, ok := r.Context().Value(woos.CtxPort).(string); ok && port != "" {
				if portMatch := m.cfg.HostManager.GetByPort(port); portMatch != nil {
					hcfg = portMatch
				}
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

	h := NewRoute(Config{
		Global:      m.cfg.Global,
		Host:        host,
		Logger:      m.cfg.Resource.Logger,
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

func (m *Manager) handleFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=31536000")
	if len(operation.Favicon) > 0 {
		http.ServeContent(w, r, "favicon.ico", zulu.ModTime, bytes.NewReader(operation.Favicon))
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

func (m *Manager) redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
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

	if port, ok := r.Context().Value(woos.CtxPort).(string); ok && port != "" {
		args = append(args, "port", port)
	}

	if m.cfg.Global != nil {
		ua := r.UserAgent()
		if m.cfg.Global.Logging.Truncate.Active() {
			args = append(args, "ua", zulu.Truncate(ua, 50))
		} else {
			args = append(args, "ua", zulu.Truncate(ua, 50))
		}
		// Add bot detection if checker exists
		if m.cfg.Global.Logging.BotChecker.Active() {
			args = append(args, "is_bot", m.botChecker.IsBot(ua))
		}
	}

	m.cfg.Resource.Logger.Fields(args...).Info(r.Method)
	*argsPtr = args
	m.logArgsPool.Put(argsPtr)
}
