package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/errors"
	"golang.org/x/crypto/bcrypt"
)

func Basic(cfg *alaye.BasicAuth) func(http.Handler) http.Handler {
	// Return passthrough if disabled
	if cfg.Enabled.No() {
		return func(next http.Handler) http.Handler { return next }
	}

	secrets := make(map[string][]byte)
	for _, u := range cfg.Users {
		parts := strings.SplitN(u, woos.Colon, 2)
		if len(parts) == 2 {
			secrets[parts[0]] = []byte(parts[1])
		}
	}

	realm := woos.Realm
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

			// Try bcrypt compare first
			if err := bcrypt.CompareHashAndPassword(validHash, []byte(pass)); err == nil {
				next.ServeHTTP(w, r)
				return
			} else if !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
				// Log non-mismatch errors
			}

			// Fallback to plaintext comparison
			if subtle.ConstantTimeCompare([]byte(pass), validHash) == 1 {
				next.ServeHTTP(w, r)
				return
			}

			unauthorized(w, realm)
		})
	}
}

func unauthorized(w http.ResponseWriter, realm string) {
	w.Header().Set(woos.HeaderWWWAuthenticate, `Basic realm="`+realm+`"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}
