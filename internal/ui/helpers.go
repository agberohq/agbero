package ui

import (
	"mime"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

func init() {
	types := map[string]string{
		".html":        "text/html; charset=utf-8",
		".css":         "text/css; charset=utf-8",
		".js":          "application/javascript; charset=utf-8",
		".json":        "application/json; charset=utf-8",
		".xml":         "text/xml; charset=utf-8",
		".svg":         "image/svg+xml",
		".txt":         "text/plain; charset=utf-8",
		".png":         "image/png",
		".jpg":         "image/jpeg",
		".jpeg":        "image/jpeg",
		".gif":         "image/gif",
		".webp":        "image/webp",
		".ico":         "image/x-icon",
		".woff2":       "font/woff2",
		".wasm":        "application/wasm",
		".md":          "text/markdown",
		".mjs":         "text/javascript; charset=utf-8",
		".webmanifest": "application/manifest+json",
		".pdf":         "application/pdf",
		".csv":         "text/csv; charset=utf-8",
		".avif":        "image/avif",
		".mp4":         "video/mp4",
		".mp3":         "audio/mpeg",
		".woff":        "font/woff",
		".zip":         "application/zip",
	}

	for ext, mimeType := range types {
		_ = mime.AddExtensionType(ext, mimeType)
	}
}

var (
	mimeCache sync.Map // ext -> type
)

func getMimeType(path string) string {
	ext := filepath.Ext(path)
	if v, ok := mimeCache.Load(ext); ok {
		return v.(string)
	}

	ctype := mime.TypeByExtension(ext)

	if ctype == "" {
		ctype = "application/octet-stream"
	} else if (strings.HasPrefix(ctype, "text/") ||
		strings.Contains(ctype, "javascript") ||
		strings.Contains(ctype, "json")) &&
		!strings.Contains(ctype, "charset") {
		ctype += "; charset=utf-8"
	}

	mimeCache.Store(ext, ctype)
	return ctype
}

//func clientAcceptsGzip(r *http.Request) bool {
//	ae := r.Header.Get("Accept-Encoding")
//	return strings.Contains(ae, "gzip")
//}

func weakETag(size int64, modTime time.Time) string {
	return `W/"` + strconv.FormatInt(size, 10) + "-" + strconv.FormatInt(modTime.UnixNano(), 10) + `"`
}

func ifNoneMatchHas(inm string, etag string) bool {
	if strings.TrimSpace(inm) == "*" {
		return true
	}
	parts := strings.Split(inm, ",")
	for _, p := range parts {
		if strings.TrimSpace(p) == etag {
			return true
		}
	}
	return false
}
