package agbero

import (
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := core.NormalizeHost(r.Host)

	hcfg := s.hostManager.Get(host)
	if hcfg == nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	// Enforce Port Binding
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

	maxBody := int64(woos.DefaultMaxBodySize)
	if hcfg.Limits != nil && hcfg.Limits.MaxBodySize > 0 {
		maxBody = hcfg.Limits.MaxBodySize
	}

	if r.ContentLength > maxBody {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	for i := range hcfg.Routes {
		route := hcfg.Routes[i]
		if core.PathMatch(r.URL.Path, route.Path) {
			s.handleRoute(w, r, &route)
			s.logRequest(host, r, start)
			return
		}
	}

	if hcfg.Web != nil {
		s.handleWeb(w, r, hcfg.Web)
		s.logRequest(host, r, start)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}
func (s *Server) handleRoute(w http.ResponseWriter, r *http.Request, route *woos.Route) {
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
func (s *Server) handleWeb(w http.ResponseWriter, r *http.Request, web *woos.Web) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Clean Path
	reqPath := filepath.Clean(r.URL.Path)
	reqPath = strings.TrimPrefix(reqPath, string(os.PathSeparator))
	if reqPath == "" || reqPath == "." {
		reqPath = "."
	}

	// 2. Open Root (Safe confinement)
	// web.Root.String() handles the default "." if empty
	dir, err := os.OpenRoot(web.Root.String())
	if err != nil {
		s.logger.Fields("err", err, "root", web.Root.String()).Error("failed to open web root")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer dir.Close()

	// 3. Open Requested File
	f, err := dir.Open(reqPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Not found", http.StatusNotFound)
		} else {
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 4. Directory Handling (Index only, no listing)
	if info.IsDir() {
		indexName := "index.html"
		if web.Index != "" {
			indexName = web.Index
		}

		// Re-open index relative to the dir
		indexPath := filepath.Join(reqPath, indexName)
		fIndex, err := dir.Open(indexPath)
		if err != nil {
			// Dir exists but no index -> Forbidden
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		defer fIndex.Close()

		infoIndex, err := fIndex.Stat()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		f = fIndex
		info = infoIndex
		reqPath = indexPath
	}

	// 5. Serve Content
	ctype := mime.TypeByExtension(filepath.Ext(reqPath))
	if ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}

	http.ServeContent(w, r, reqPath, info.ModTime(), f)
}
