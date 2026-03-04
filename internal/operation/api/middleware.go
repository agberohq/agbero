package api

import (
	"net/http"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/pkg/security"
	"github.com/olekukonko/ll"
)

func Auth(tm *security.Manager, logger *ll.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error": "authorization header required"}`, http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				http.Error(w, `{"error": "invalid authorization format"}`, http.StatusUnauthorized)
				return
			}

			token := parts[1]
			serviceName, err := tm.Verify(token)
			if err != nil {
				logger.Fields("remote", r.RemoteAddr, "err", err).Warn("api auth failed")
				http.Error(w, `{"error": "invalid or expired token"}`, http.StatusForbidden)
				return
			}

			// Add service name to header for downstream handlers if needed
			r.Header.Set("X-Agbero-Service", serviceName)

			next.ServeHTTP(w, r)
		})
	}
}
