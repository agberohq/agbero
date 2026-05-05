package web

import (
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/raw/afs"
	"github.com/agberohq/agbero/internal/pkg/raw/ahash"
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

// isHTMLMIME reports whether mt is an HTML content type.
func isHTMLMIME(mt string) bool {
	return mt == "text/html" || mt == "text/html; charset=utf-8"
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

// isSafeRedirectPath rejects protocol-relative URLs and any path containing
// CR/LF characters that could be used for response splitting.
func isSafeRedirectPath(p string) bool {
	if strings.HasPrefix(p, "//") {
		return false
	}
	if strings.ContainsAny(p, "\r\n") {
		return false
	}
	return true
}

// formatContentDisposition returns a properly quoted and escaped
// Content-Disposition header value per RFC 6266.
func formatContentDisposition(filename string) string {
	escaped := strings.ReplaceAll(filename, `"`, `\"`)
	return fmt.Sprintf(`attachment; filename="%s"`, escaped)
}

// sanitizePHPHeaders removes dangerous CGI/FastCGI headers from the incoming
// request before forwarding to PHP-FPM. Delegates to def.SanitizeFastCGIHeaders
// which is the single authoritative implementation shared with the generic
// FastCGI backend in xhttp/backend.go.
func sanitizePHPHeaders(r *http.Request) http.Header {
	return woos.SanitizeFastCGIHeaders(r)
}
