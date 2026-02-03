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
					// Capture stack trace
					stack := string(debug.Stack())

					// Log structured error using ll
					// We use .Fields() to attach metadata, then .Error() to log it
					logger.Fields(
						"panic", err,
						"stack", stack,
						"method", r.Method,
						"path", r.URL.Path,
						"remote", r.RemoteAddr,
					).Error("http request panic recovered")

					// Check if the connection is broken (optional, but good practice)
					// If the header was not written, send 500
					// Note: If the panic happened after writing the header, this might be superfluous,
					// but http.Error handles that check internally usually.
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(`{"error": "Internal Server Error"}`))
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
