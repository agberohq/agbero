// internal/middleware/auth/auth.go
package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

func Basic(cfg *woos.BasicAuthConfig) func(http.Handler) http.Handler {
	secrets := make(map[string]string)
	for _, u := range cfg.Users {
		parts := strings.SplitN(u, ":", 2)
		if len(parts) == 2 {
			secrets[parts[0]] = parts[1]
		}
	}

	realm := "Restricted"
	if cfg.Realm != "" {
		realm = cfg.Realm
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()

			if !ok {
				unauthorized(w, realm)
				return
			}

			validPass, exists := secrets[user]
			if !exists {
				unauthorized(w, realm)
				return
			}

			if subtle.ConstantTimeCompare([]byte(pass), []byte(validPass)) != 1 {
				unauthorized(w, realm)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func unauthorized(w http.ResponseWriter, realm string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}
