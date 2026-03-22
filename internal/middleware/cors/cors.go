package cors

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
)

func New(cfg *alaye.CORS) func(http.Handler) http.Handler {
	if cfg.Enabled.NotActive() {
		return func(next http.Handler) http.Handler { return next }
	}

	allowAllOrigins := slices.Contains(cfg.AllowedOrigins, "*")

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

			w.Header().Add("Vary", "Origin")

			allowedOrigin := ""
			if allowAllOrigins {
				allowedOrigin = "*"

				if cfg.AllowCredentials {
					allowedOrigin = origin
				}
			} else {
				originLower := strings.ToLower(origin)
				for _, o := range cfg.AllowedOrigins {
					oLower := strings.ToLower(o)

					if oLower == originLower {
						allowedOrigin = origin
						break
					}

					if strings.Contains(oLower, "*") {
						parts := strings.SplitN(oLower, "*", 2)
						if len(parts) == 2 {
							if strings.HasPrefix(originLower, parts[0]) && strings.HasSuffix(originLower, parts[1]) {
								allowedOrigin = origin
								break
							}
						}
					}
				}
			}

			if allowedOrigin == "" {
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			if cfg.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
				w.Header().Set("Access-Control-Allow-Methods", allowMethods)
				w.Header().Set("Access-Control-Allow-Headers", allowHeaders)
				w.Header().Set("Access-Control-Max-Age", maxAge)
				w.WriteHeader(http.StatusNoContent)
				return
			}

			if exposeHeaders != "" {
				w.Header().Set("Access-Control-Expose-Headers", exposeHeaders)
			}

			next.ServeHTTP(w, r)
		})
	}
}
