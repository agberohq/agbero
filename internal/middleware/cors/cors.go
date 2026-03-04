package cors

import (
	"net/http"
	"strconv"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
)

// New returns CORS middleware based on configuration.
// Returns no-op handler if CORS is disabled.
func New(cfg *alaye.CORS) func(http.Handler) http.Handler {
	if cfg.Enabled.NotActive() {
		return func(next http.Handler) http.Handler { return next }
	}

	allowAllOrigins := false
	for _, o := range cfg.AllowedOrigins {
		if o == "*" {
			allowAllOrigins = true
			break
		}
	}

	allowMethods := strings.Join(cfg.AllowedMethods, ", ")
	allowHeaders := strings.Join(cfg.AllowedHeaders, ", ")
	exposeHeaders := strings.Join(cfg.ExposedHeaders, ", ")
	maxAge := strconv.Itoa(cfg.MaxAge)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Always add Vary header
			w.Header().Add("Vary", "Origin")

			allowedOrigin := ""
			if allowAllOrigins {
				allowedOrigin = "*"
				// Cannot use "*" with credentials
				if cfg.AllowCredentials {
					allowedOrigin = origin
				}
			} else {
				for _, o := range cfg.AllowedOrigins {
					if strings.EqualFold(o, origin) {
						allowedOrigin = origin
						break
					}
				}
			}

			if allowedOrigin == "" {
				// Origin not allowed, proceed without CORS headers
				next.ServeHTTP(w, r)
				return
			}

			// Set basic CORS headers
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			if cfg.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			// Handle preflight requests
			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				w.Header().Set("Access-Control-Allow-Methods", allowMethods)
				w.Header().Set("Access-Control-Allow-Headers", allowHeaders)
				w.Header().Set("Access-Control-Max-Age", maxAge)
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// Set exposed headers for actual requests
			if exposeHeaders != "" {
				w.Header().Set("Access-Control-Expose-Headers", exposeHeaders)
			}

			next.ServeHTTP(w, r)
		})
	}
}
