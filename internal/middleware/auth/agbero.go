package auth

import (
	"net/http"
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/pkg/security"
	"github.com/olekukonko/ll"
)

// Internal authenticates requests using PPK (EdDSA) service tokens.
// On success it sets X-Agbero-Service and X-Agbero-JTI headers so downstream
// handlers can read the service identity and JTI without re-parsing the token.
// isRevoked is optional — pass nil to skip revocation checking.
func Internal(tm *security.PPK, logger *ll.Logger, isRevoked func(jti string) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get(def.AuthorizationHeaderKey)
			if authHeader == "" {
				http.Error(w, `{"error": "authorization header required"}`, http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				http.Error(w, `{"error": "invalid authorization format"}`, http.StatusUnauthorized)
				return
			}

			verified, err := tm.Verify(parts[1])
			if err != nil {
				logger.Fields("remote", r.RemoteAddr, "err", err).Warn("api auth failed")
				http.Error(w, `{"error": "invalid or expired token"}`, http.StatusForbidden)
				return
			}

			if isRevoked != nil && verified.JTI != "" && isRevoked(verified.JTI) {
				logger.Fields("remote", r.RemoteAddr, "jti", verified.JTI).Warn("api auth: revoked token")
				http.Error(w, `{"error": "token revoked"}`, http.StatusForbidden)
				return
			}

			r.Header.Set(def.HeaderXAgberoService, verified.Service)
			r.Header.Set(def.HeaderXAgberoJTI, verified.JTI)
			next.ServeHTTP(w, r)
		})
	}
}
