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

	"github.com/agberohq/agbero/internal/pkg/raw/afs"
	"github.com/agberohq/agbero/internal/pkg/raw/ahash"
)

const (
	baseDecimalFormat = 10
	hexDecimalFormat  = 16
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
	mimeCache sync.Map
)

// getMimeType determines the appropriate Content-Type for requested assets safely.
// Defaults aggressively to octet-stream for unidentifiable binary downloads.
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

// ifNoneMatchHas verifies existing client cache states against newly generated identifiers.
// Recognizes universal asterisks honoring conditional HTTP fetching completely.
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

// isCompressibleMIME reports whether the MIME type benefits from on-the-fly gzip processing.
// Guards against burning CPU cycles trying to compress pre-compressed media formats.
func isCompressibleMIME(mt string) bool {
	for _, prefix := range compressibleMIME {
		if strings.HasPrefix(mt, prefix) {
			return true
		}
	}
	return false
}

// detectContentType reads introductory bytes mapping file signatures accurately.
// Reverts the read pointer cleanly enabling normal transfer operations afterward.
func detectContentType(f *os.File) string {
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	_, _ = f.Seek(0, 0)
	if n > 0 {
		return http.DetectContentType(buf[:n])
	}
	return "application/octet-stream"
}

// weakETag constructs a non-cryptographic identifier based on file metadata directly.
// Incorporates hardware-accelerated CRC32 to ensure generation is effectively zero-cost.
func weakETag(path string, size int64, modTime time.Time) string {
	var sb strings.Builder
	sb.WriteString(strconv.FormatInt(size, baseDecimalFormat))
	sb.WriteByte('-')
	sb.WriteString(strconv.FormatInt(modTime.UnixNano(), baseDecimalFormat))
	sb.WriteByte('-')
	sb.WriteString(strconv.FormatUint(afs.InodeOf(path), baseDecimalFormat))
	return `W/"` + strconv.FormatUint(ahash.CRC32Hash(sb.String()), hexDecimalFormat) + `"`
}

// isMarkdownPath verifies file extensions before attempting structural conversions.
// Constrains goldmark execution preventing unnecessary load against foreign inputs.
func isMarkdownPath(path string) bool {
	return markdownExts[strings.ToLower(filepath.Ext(path))]
}
