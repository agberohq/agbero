package headers

import (
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

// headerWriter intercepts the response to modify headers
type headerWriter struct {
	http.ResponseWriter
	ops alaye.Header
}

func (w *headerWriter) WriteHeader(statusCode int) {
	applyHeaders(w.ResponseWriter.Header(), w.ops)
	w.ResponseWriter.WriteHeader(statusCode)
}
