package mcp

import (
	"context"
	"net/http"
	"strings"
)

type claimsContextKey struct{}

// WithClaims attaches verified token claims to a request context. The daemon's
// HTTP middleware does this before handing the request to the SDK handler.
func WithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey{}, claims)
}

// ClaimsFromContext returns the verified claims, or nil when the request did
// not pass through the MCP auth middleware.
func ClaimsFromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsContextKey{}).(*Claims)
	return c
}

// AuthMiddleware verifies an MCP bearer token, checks the optional JTI
// revocation callback, and attaches the claims to the request context. The IP
// allowlist must run before this middleware.
func AuthMiddleware(store *TokenStore, revoked func(string) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if store == nil {
				http.Error(w, `{"error":"mcp_unavailable"}`, http.StatusServiceUnavailable)
				return
			}
			header := strings.TrimSpace(r.Header.Get("Authorization"))
			if len(header) < len("Bearer ")+1 || !strings.EqualFold(header[:len("Bearer ")], "Bearer ") {
				http.Error(w, `{"error":"missing_mcp_token"}`, http.StatusUnauthorized)
				return
			}
			claims, err := store.Verify(strings.TrimSpace(header[len("Bearer "):]))
			if err != nil {
				status := http.StatusUnauthorized
				if err == ErrKeeperLocked {
					status = http.StatusServiceUnavailable
				}
				http.Error(w, `{"error":"invalid_mcp_token"}`, status)
				return
			}
			if revoked != nil && revoked(claims.ID) {
				http.Error(w, `{"error":"revoked_mcp_token"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
		})
	}
}

func readScope(ctx context.Context) bool {
	return HasScope(ClaimsFromContext(ctx), ScopeRead)
}
