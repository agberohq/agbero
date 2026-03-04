package errorpages

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"github.com/olekukonko/mappo"
)

// Pre-allocated status strings to avoid strconv.Itoa allocations
var statusStrings = func() [600]string {
	var arr [600]string
	for i := 100; i < 600; i++ {
		arr[i] = strconv.Itoa(i)
	}
	return arr
}()

// fileCacheEntry holds cached file content with modification time
type fileCacheEntry struct {
	content []byte
	modTime int64
}

type Config struct {
	RoutePages  alaye.ErrorPages
	HostPages   alaye.ErrorPages
	GlobalPages alaye.ErrorPages
	EnableCache bool // Cache error pages in memory to avoid disk I/O
}

func New(cfg Config) func(http.Handler) http.Handler {
	var cache *mappo.Sharded[string, *fileCacheEntry]
	if cfg.EnableCache {
		cache = mappo.NewSharded[string, *fileCacheEntry]()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ew := &errorWriter{
				ResponseWriter: w,
				cfg:            cfg,
				req:            r,
				cache:          cache,
			}
			next.ServeHTTP(ew, r)
		})
	}
}

type errorWriter struct {
	http.ResponseWriter
	cfg         Config
	req         *http.Request
	cache       *mappo.Sharded[string, *fileCacheEntry]
	wroteHeader bool
	code        int
	intercepted bool // true if we served a custom error page
}

func (w *errorWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.code = code

	if code >= 400 {
		if w.tryServeErrorPage(code) {
			w.intercepted = true
			w.wroteHeader = true
			return
		}
	}

	w.ResponseWriter.WriteHeader(code)
	w.wroteHeader = true
}

func (w *errorWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.intercepted {
		return len(b), nil // Discard original body if we served custom page
	}
	return w.ResponseWriter.Write(b)
}

func (w *errorWriter) tryServeErrorPage(code int) bool {
	codeStr := statusStrings[code]

	path := w.findErrorPagePath(codeStr)
	if path == "" {
		return false
	}

	content, ok := w.loadErrorPage(path)
	if !ok {
		return false
	}

	w.ResponseWriter.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.ResponseWriter.Header().Set("Content-Length", strconv.Itoa(len(content)))
	w.ResponseWriter.WriteHeader(code)
	w.ResponseWriter.Write(content)
	return true
}

func (w *errorWriter) findErrorPagePath(codeStr string) string {
	if p := w.cfg.RoutePages.Pages[codeStr]; p != "" {
		return p
	}
	if w.cfg.RoutePages.Default != "" {
		return w.cfg.RoutePages.Default
	}

	if p := w.cfg.HostPages.Pages[codeStr]; p != "" {
		return p
	}
	if w.cfg.HostPages.Default != "" {
		return w.cfg.HostPages.Default
	}

	if p := w.cfg.GlobalPages.Pages[codeStr]; p != "" {
		return p
	}
	return w.cfg.GlobalPages.Default
}

func (w *errorWriter) loadErrorPage(path string) ([]byte, bool) {
	if w.cache == nil {
		return w.readFile(path)
	}

	if cached, ok := w.cache.Get(path); ok {
		if info, err := os.Stat(path); err == nil && info.ModTime().Unix() == cached.modTime {
			return cached.content, true
		}
		// Cache stale or file gone, delete entry
		w.cache.Delete(path)
	}

	content, ok := w.readFile(path)
	if !ok {
		return nil, false
	}

	if info, err := os.Stat(path); err == nil {
		w.cache.Set(path, &fileCacheEntry{
			content: content,
			modTime: info.ModTime().Unix(),
		})
	}

	return content, true
}

func (w *errorWriter) readFile(path string) ([]byte, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()

	info, err := f.Stat()
	var buf bytes.Buffer
	if err == nil && info.Size() > 0 && info.Size() < 10*1024*1024 {
		buf.Grow(int(info.Size()))
	}

	if _, err := buf.ReadFrom(f); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

func (w *errorWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *errorWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijack not supported")
}
