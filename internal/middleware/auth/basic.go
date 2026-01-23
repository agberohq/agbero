package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/errors"
	"golang.org/x/crypto/bcrypt"
)

func Basic(cfg *alaye.BasicAuth) func(http.Handler) http.Handler {
	secrets := make(map[string][]byte)
	for _, u := range cfg.Users {
		parts := strings.SplitN(u, ":", 2)
		if len(parts) == 2 {
			secrets[parts[0]] = []byte(parts[1]) // Assume hashed; plaintext fallback logs warn
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

			validHash, exists := secrets[user]
			if !exists {
				unauthorized(w, realm)
				return
			}

			// Try bcrypt compare (constant-time internally)
			if err := bcrypt.CompareHashAndPassword(validHash, []byte(pass)); err == nil {
				next.ServeHTTP(w, r)
				return
			} else if !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				// Log non-mismatch errors (e.g., invalid hash format)
				// Note: In prod, avoid logging to prevent timing leaks
			}

			// Fallback plaintext (insecure; warn)
			if subtle.ConstantTimeCompare([]byte(pass), validHash) == 1 {
				// Log warn: "plaintext auth used" (once?)
				next.ServeHTTP(w, r)
				return
			}

			unauthorized(w, realm)
		})
	}
}

func unauthorized(w http.ResponseWriter, realm string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}
