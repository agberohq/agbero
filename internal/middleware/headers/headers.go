package headers

import (
	"bufio"
	"fmt"
	"net"
	"net/http"

	"github.com/agberohq/agbero/internal/core/alaye"
)

func Headers(cfg *alaye.Headers) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Modify Request Headers (Going Upstream)
			if cfg.Request.Enabled.Active() {
				applyHeaders(r.Header, cfg.Request)
			}

			// Modify Response Headers (Going Downstream)
			// We need to wrap the ResponseWriter to modify headers before WriteHeader is called.
			if cfg.Response.Enabled.Active() {
				writer := &headerWriter{ResponseWriter: w, ops: cfg.Response}
				next.ServeHTTP(writer, r)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}

func applyHeaders(h http.Header, ops alaye.Header) {
	for _, k := range ops.Remove {
		h.Del(k)
	}
	for k, v := range ops.Set {
		h.Set(k, v)
	}
	for k, v := range ops.Add {
		h.Add(k, v)
	}
}

// headerWriter intercepts the response to modify headers.
//
// It explicitly delegates http.Flusher and http.Hijacker to the underlying
// ResponseWriter so that embedding http.ResponseWriter does not mask those
// interfaces on the concrete type. Without this delegation:
//   - WebSocket upgrades fail with HTTP 500 because httputil.ReverseProxy
//     cannot hijack the connection (http.Hijacker type assertion returns false).
//   - Server-Sent Events / streaming responses buffer entirely in memory
//     because the proxy cannot flush incremental chunks (http.Flusher
//     type assertion returns false).
type headerWriter struct {
	http.ResponseWriter
	ops alaye.Header
}

func (w *headerWriter) WriteHeader(statusCode int) {
	applyHeaders(w.ResponseWriter.Header(), w.ops)
	w.ResponseWriter.WriteHeader(statusCode)
}

// Flush delegates to the underlying ResponseWriter's Flush method if it
// implements http.Flusher, enabling SSE and streaming proxying.
func (w *headerWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack delegates to the underlying ResponseWriter's Hijack method if it
// implements http.Hijacker, enabling WebSocket and other protocol upgrades.
func (w *headerWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijack not supported by underlying writer")
}
