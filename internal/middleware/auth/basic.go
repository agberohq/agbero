package auth

import (
	"net/http"
	"os"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/ll"
	"golang.org/x/crypto/bcrypt"
)

// Basic returns middleware that enforces HTTP Basic authentication against bcrypt-hashed credentials.
// Plaintext passwords are rejected with an error log; only bcrypt hashes are accepted.
func Basic(cfg *alaye.BasicAuth, logger *ll.Logger) func(http.Handler) http.Handler {
	if cfg.Enabled.NotActive() {
		return func(next http.Handler) http.Handler { return next }
	}

	secrets := make(map[string][]byte)
	for _, u := range cfg.Users {
		parts := strings.SplitN(u, def.Colon, 2)
		if len(parts) != 2 {
			continue
		}
		username := strings.TrimSpace(parts[0])
		rawSecret := strings.TrimSpace(parts[1])
		if username == "" || rawSecret == "" {
			continue
		}
		// Resolve explicit secret-store references (ss://, keeper://, …). A
		// bcrypt hash contains "$" and must never be run through the generic
		// Value expander, so only refs take this path.
		hash := rawSecret
		if expect.Value(rawSecret).IsSecretStoreRef() {
			resolved, err := expect.Value(rawSecret).ResolveErr(os.Getenv)
			if err != nil {
				logger.Fields("user", username, "err", err).Error("basic_auth: resolve secret reference failed")
				continue
			}
			hash = resolved
		}
		secrets[username] = []byte(hash)
	}

	realm := def.Realm
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

			err := bcrypt.CompareHashAndPassword(validHash, []byte(pass))
			if err == nil {
				next.ServeHTTP(w, r)
				return
			}

			if err != bcrypt.ErrMismatchedHashAndPassword {
				logger.Fields(
					"user", user,
					"err", err.Error(),
				).Error("basic_auth: non-bcrypt password hash detected for user — only bcrypt hashes are accepted")
			}

			unauthorized(w, realm)
		})
	}
}

// unauthorized writes a 401 response with the WWW-Authenticate challenge header.
func unauthorized(w http.ResponseWriter, realm string) {
	w.Header().Set(def.HeaderWWWAuthenticate, `Basic realm="`+realm+`"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}
