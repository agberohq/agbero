package middleware

import (
	"net/http"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

func Headers(cfg *woos.HeadersConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Modify Request Headers (Going Upstream)
			if cfg.Request != nil {
				applyHeaders(r.Header, cfg.Request)
			}

			// 2. Modify Response Headers (Going Downstream)
			// We need to wrap the ResponseWriter to modify headers before WriteHeader is called.
			if cfg.Response != nil {
				writer := &headerWriter{ResponseWriter: w, ops: cfg.Response}
				next.ServeHTTP(writer, r)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}

func applyHeaders(h http.Header, ops *woos.HeaderOperations) {
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
	ops *woos.HeaderOperations
}

func (w *headerWriter) WriteHeader(statusCode int) {
	applyHeaders(w.ResponseWriter.Header(), w.ops)
	w.ResponseWriter.WriteHeader(statusCode)
}
