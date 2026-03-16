package web

import (
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/agberohq/agbero/internal/dependency"
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

func ifNoneMatchHas(inm string, etag string) bool {
	if strings.TrimSpace(inm) == "*" {
		return true
	}
	parts := strings.SplitSeq(inm, ",")
	for p := range parts {
		if strings.TrimSpace(p) == etag {
			return true
		}
	}
	return false
}

// isCompressibleMIME reports whether the MIME type benefits from on-the-fly gzip.
func isCompressibleMIME(mt string) bool {
	for _, prefix := range compressibleMIME {
		if strings.HasPrefix(mt, prefix) {
			return true
		}
	}
	return false
}

// detectContentType reads up to 512 bytes from f to sniff the MIME type
// and seeks back to the start. Falls back to application/octet-stream.
func detectContentType(f *os.File) string {
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	_, _ = f.Seek(0, 0)
	if n > 0 {
		return http.DetectContentType(buf[:n])
	}
	return "application/octet-stream"
}

// weakETag builds a weak ETag from size, modtime, and inode number.
// Falls back to inode 0 on platforms without inode support.
func weakETag(path string, size int64, modTime time.Time) string {
	var sb strings.Builder
	sb.WriteString(strconv.FormatInt(size, 10))
	sb.WriteByte('-')
	sb.WriteString(strconv.FormatInt(modTime.UnixNano(), 10))
	sb.WriteByte('-')
	sb.WriteString(strconv.FormatUint(dependency.InodeOf(path), 10))
	return `W/"` + strconv.FormatUint(fnv64a(sb.String()), 16) + `"`
}

// isMarkdownPath reports whether the file extension is a recognised Markdown type.
func isMarkdownPath(path string) bool {
	return markdownExts[strings.ToLower(filepath.Ext(path))]
}

// fnv64a is a non-cryptographic FNV-1a 64-bit hash used for ETag generation.
func fnv64a(s string) uint64 {
	const (
		offset64 uint64 = 14695981039346656037
		prime64  uint64 = 1099511628211
	)
	h := offset64
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime64
	}
	return h
}
