package handlers

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
)

type webHandler struct {
	route  *alaye.Route
	logger *ll.Logger
}

var mimeCache sync.Map // ext -> type

func (h *webHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	root := h.route.Web.Root.String()
	if root == "" {
		root = "."
	}

	// SECURITY: Use os.OpenRoot to prevent path traversal
	dir, err := os.OpenRoot(root)
	if err != nil {
		h.logger.Fields("err", err, "root", root).Error("failed to open web root")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer dir.Close()

	// Clean and get the requested path within the root
	reqPath := filepath.Clean(r.URL.Path)
	reqPath = strings.TrimPrefix(reqPath, string(os.PathSeparator))
	if reqPath == "" || reqPath == "." {
		reqPath = "."
	}

	// Try gzipped version first if client supports it
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		gzPath := reqPath + ".gz"
		if reqPath == "." || reqPath == "" {
			indexName := "index.html"
			if h.route.Web.Index != "" {
				indexName = h.route.Web.Index
			}
			gzPath = indexName + ".gz"
		}

		fGz, err := dir.Open(gzPath)
		if err == nil {
			defer fGz.Close()
			infoGz, err := fGz.Stat()
			if err == nil && !infoGz.IsDir() {
				origType := getMimeType(strings.TrimSuffix(gzPath, ".gz"))
				if origType != "" {
					w.Header().Set("Content-Type", origType)
				}
				w.Header().Set("Content-Encoding", "gzip")
				http.ServeContent(w, r, gzPath, infoGz.ModTime(), fGz)
				return
			}
		}
	}

	// Serve regular file
	f, err := dir.Open(reqPath)
	if err != nil {
		if err == fs.ErrNotExist || err == fs.ErrPermission {
			http.Error(w, "Not Found", http.StatusNotFound)
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

	// Handle directory - serve index file
	if info.IsDir() {
		indexName := "index.html"
		if h.route.Web.Index != "" {
			indexName = h.route.Web.Index
		}

		indexPath := filepath.Join(reqPath, indexName)
		fIndex, err := dir.Open(indexPath)
		if err != nil {
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

	// Set content type
	ctype := getMimeType(reqPath)
	if ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}

	http.ServeContent(w, r, reqPath, info.ModTime(), f)
}

func getMimeType(path string) string {
	ext := filepath.Ext(path)
	if v, ok := mimeCache.Load(ext); ok {
		return v.(string)
	}

	// Simple mime type mapping (can be expanded)
	var ctype string
	switch strings.ToLower(ext) {
	case ".html", ".htm":
		ctype = "text/html; charset=utf-8"
	case ".css":
		ctype = "text/css; charset=utf-8"
	case ".js":
		ctype = "application/javascript; charset=utf-8"
	case ".json":
		ctype = "application/json; charset=utf-8"
	case ".png":
		ctype = "image/png"
	case ".jpg", ".jpeg":
		ctype = "image/jpeg"
	case ".gif":
		ctype = "image/gif"
	case ".svg":
		ctype = "image/svg+xml"
	case ".pdf":
		ctype = "application/pdf"
	case ".txt", ".md":
		ctype = "text/plain; charset=utf-8"
	case ".ico":
		ctype = "image/x-icon"
	case ".woff":
		ctype = "font/woff"
	case ".woff2":
		ctype = "font/woff2"
	case ".ttf":
		ctype = "font/ttf"
	case ".eot":
		ctype = "application/vnd.ms-fontobject"
	case ".otf":
		ctype = "font/otf"
	case ".xml":
		ctype = "application/xml"
	case ".webp":
		ctype = "image/webp"
	case ".avif":
		ctype = "image/avif"
	default:
		ctype = "application/octet-stream"
	}

	if ctype != "" {
		mimeCache.Store(ext, ctype)
	}
	return ctype
}
