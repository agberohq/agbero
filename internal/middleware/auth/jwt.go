package auth

import (
	"fmt"
	"net/http"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/golang-jwt/jwt/v5"
	"github.com/olekukonko/errors"
)

func JWT(cfg *alaye.JWTAuth) func(http.Handler) http.Handler {
	secretBytes := []byte(cfg.Secret)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get(woos.AuthorizationHeaderKey)
			if authHeader == "" {
				http.Error(w, `{"error":"missing_authorization"}`, http.StatusUnauthorized)
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, woos.HeaderKeyBearer+" ")

			// Parse & Validate
			token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
				// Enforce HMAC for simplicity in this iteration
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

			// Validate Issuer/Audience if configured
			if cfg.Issuer != "" {
				if iss, _ := claims.GetIssuer(); iss != cfg.Issuer {
					http.Error(w, `{"error":"invalid_issuer"}`, http.StatusUnauthorized)
					return
				}
			}

			// Extract claims to headers
			for claimKey, headerName := range cfg.ClaimMap {
				if val, ok := claims[claimKey]; ok {
					r.Header.Set(headerName, fmt.Sprintf("%v", val))
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
