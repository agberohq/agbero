package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/golang-jwt/jwt/v5"
	"github.com/olekukonko/errors"
)

type contextKey string

const ClaimsContextKey contextKey = "jwt_claims"

func JWT(cfg *alaye.JWTAuth) func(http.Handler) http.Handler {
	if cfg.Enabled.NotActive() {
		return func(next http.Handler) http.Handler { return next }
	}

	secretBytes := []byte(cfg.Secret.String())

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get(woos.AuthorizationHeaderKey)
			if authHeader == "" {
				http.Error(w, `{"error":"missing_authorization"}`, http.StatusUnauthorized)
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, woos.HeaderKeyBearer+" ")

			token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, errors.Newf("%w: %v", woos.ErrUnexpectedSigningMethod, token.Header["alg"])
				}
				return secretBytes, nil
			})

			if err != nil || !token.Valid {
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, `{"error":"invalid_claims"}`, http.StatusUnauthorized)
				return
			}

			if cfg.Issuer != "" {
				if iss, _ := claims.GetIssuer(); iss != cfg.Issuer {
					http.Error(w, `{"error":"invalid_issuer"}`, http.StatusUnauthorized)
					return
				}
			}

			if scope, _ := claims["scope"].(string); scope == "challenge" {
				http.Error(w, `{"error":"insufficient_scope"}`, http.StatusForbidden)
				return
			}

			for _, headerName := range cfg.ClaimMap {
				r.Header.Del(headerName)
			}

			for claimKey, headerName := range cfg.ClaimMap {
				if val, ok := claims[claimKey]; ok {
					r.Header.Set(headerName, fmt.Sprintf("%v", val))
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// JWTWithRevocation validates a JWT token identically to JWT but additionally
// checks the jti claim against the provided isRevoked function, rejecting
// tokens that have been explicitly revoked (e.g. via logout).
func JWTWithRevocation(cfg *alaye.JWTAuth, isRevoked func(jti string) bool) func(http.Handler) http.Handler {
	if cfg.Enabled.NotActive() {
		return func(next http.Handler) http.Handler { return next }
	}

	secretBytes := []byte(cfg.Secret.String())

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get(woos.AuthorizationHeaderKey)
			if authHeader == "" {
				http.Error(w, `{"error":"missing_authorization"}`, http.StatusUnauthorized)
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, woos.HeaderKeyBearer+" ")

			token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, errors.Newf("%w: %v", woos.ErrUnexpectedSigningMethod, token.Header["alg"])
				}
				return secretBytes, nil
			})

			if err != nil || !token.Valid {
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, `{"error":"invalid_claims"}`, http.StatusUnauthorized)
				return
			}

			if cfg.Issuer != "" {
				if iss, _ := claims.GetIssuer(); iss != cfg.Issuer {
					http.Error(w, `{"error":"invalid_issuer"}`, http.StatusUnauthorized)
					return
				}
			}

			if jti, _ := claims["jti"].(string); jti != "" && isRevoked(jti) {
				http.Error(w, `{"error":"token_revoked"}`, http.StatusUnauthorized)
				return
			}

			if scope, _ := claims["scope"].(string); scope == "challenge" {
				http.Error(w, `{"error":"insufficient_scope"}`, http.StatusForbidden)
				return
			}

			for _, headerName := range cfg.ClaimMap {
				r.Header.Del(headerName)
			}

			for claimKey, headerName := range cfg.ClaimMap {
				if val, ok := claims[claimKey]; ok {
					r.Header.Set(headerName, fmt.Sprintf("%v", val))
				}
			}

			ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func JWTWithRevocationAndScope(cfg *alaye.JWTAuth, isRevoked func(jti string) bool) func(http.Handler) http.Handler {
	return JWTWithRevocation(cfg, isRevoked)
}

func GetClaims(r *http.Request) (jwt.MapClaims, bool) {
	claims, ok := r.Context().Value(ClaimsContextKey).(jwt.MapClaims)
	return claims, ok
}
