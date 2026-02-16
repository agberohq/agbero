package recovery

import (
	"net/http"
	"runtime/debug"

	"github.com/olekukonko/ll"
)

// New creates a middleware that recovers from panics, logs the error with a stack trace,
// and returns a 500 Internal Server Error to the client.
func New(logger *ll.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					stack := string(debug.Stack())

					logger.Fields(
						"panic", err,
						"stack", stack,
						"method", r.Method,
						"path", r.URL.Path,
						"remote", r.RemoteAddr,
					).Error("http request panic recovered")

					// Check if headers already written
					// We can't easily check, so try to write error
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(`{"error": "Internal Server Error"}`))
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
