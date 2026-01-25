package agbero

import (
	"net/http"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
)

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := core.NormalizeHost(r.Host)

	hcfg := s.hostManager.Get(host)
	if hcfg == nil {
		http.Error(w, "Host not found", http.StatusNotFound)
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
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	router := s.hostManager.GetRouter(host)
	if router == nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	// s.logger.Debug(r.URL.Path)
	res := router.Find(r.URL.Path)
	if res.Route != nil {
		s.handleRoute(w, r, res.Route)
		s.logRequest(host, r, start)
		return
	}
	http.Error(w, "Not found", http.StatusNotFound)
}

func (s *Server) handleRoute(w http.ResponseWriter, r *http.Request, route *alaye.Route) {
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

				// --- FIX START ---
				// If we stripped everything (e.g. /consul -> ""), ensure path is "/"
				if r.URL.Path == "" {
					r.URL.Path = "/"
				}
				// --- FIX END ---

				break
			}
		}
	}

	h := s.getOrBuildRouteHandler(route)
	h.ServeHTTP(w, r)

	r.URL.Path = originalPath
	r.URL.RawPath = originalRawPath
}
