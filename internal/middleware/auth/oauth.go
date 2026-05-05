package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/gitlab"
	"github.com/markbates/goth/providers/google"
	"github.com/markbates/goth/providers/openidConnect"
	"github.com/olekukonko/errors"
)

const cookieValueSeparator = "."

// OAuth returns middleware that enforces OAuth authentication for a route.
// The session cookie is HMAC-SHA256 signed with cfg.CookieSecret and verified on every request.
func OAuth(cfg *alaye.OAuth) func(http.Handler) http.Handler {
	if cfg.Enabled.NotActive() {
		return func(next http.Handler) http.Handler { return next }
	}

	provider, err := getProvider(cfg)
	if err != nil {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "OAuth Configuration Error: "+err.Error(), http.StatusInternalServerError)
			})
		}
	}

	secret := []byte(cfg.CookieSecret.String())

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isCallbackRequest(r, cfg.RedirectURL) {
				handleGothCallback(w, r, provider, cfg, secret)
				return
			}

			cookie, err := r.Cookie(def.SessionCookieName)
			if err == nil && cookie.Value != "" {
				if verifySessionCookie(cookie.Value, secret) {
					next.ServeHTTP(w, r)
					return
				}
				clearCookie(w, def.SessionCookieName)
			}

			startGothFlow(w, r, provider)
		})
	}
}

// getProvider constructs the goth.Provider from the OAuth configuration.
// Returns an error for unknown or misconfigured providers.
func getProvider(cfg *alaye.OAuth) (goth.Provider, error) {
	callback := cfg.RedirectURL
	key := cfg.ClientID
	secret := cfg.ClientSecret.String()
	scopes := cfg.Scopes

	switch strings.ToLower(cfg.Provider) {
	case def.ProviderGoogle:
		return google.New(key, secret, callback, scopes...), nil
	case def.ProviderGitHub:
		return github.New(key, secret, callback, scopes...), nil
	case def.ProviderGitLab:
		return gitlab.New(key, secret, callback, scopes...), nil
	case def.ProviderOIDC, def.ProviderGeneric:
		if cfg.AuthURL == "" {
			return nil, def.ErrInvalidAuthURL
		}
		return openidConnect.New(key, secret, callback, cfg.AuthURL, scopes...)
	default:
		return nil, errors.Newf("%w: %s", def.ErrUnsupportedProvider, cfg.Provider)
	}
}

// startGothFlow initiates the OAuth redirect flow and stores the provider session in a cookie.
// The state cookie is short-lived and HttpOnly to prevent CSRF.
func startGothFlow(w http.ResponseWriter, r *http.Request, provider goth.Provider) {
	state, err := generateState()
	if err != nil {
		http.Error(w, "Failed to generate auth state", http.StatusInternalServerError)
		return
	}

	sess, err := provider.BeginAuth(state)
	if err != nil {
		http.Error(w, "Failed to start auth: "+err.Error(), http.StatusInternalServerError)
		return
	}

	authURL, err := sess.GetAuthURL()
	if err != nil {
		http.Error(w, "Failed to get auth url: "+err.Error(), http.StatusInternalServerError)
		return
	}

	sessData := sess.Marshal()
	encodedSess := base64.StdEncoding.EncodeToString([]byte(sessData))

	http.SetCookie(w, &http.Cookie{
		Name:     def.GothSessionCookie,
		Value:    encodedSess,
		Path:     def.Slash,
		HttpOnly: true,
		Secure:   isSecure(r),
		Expires:  time.Now().Add(def.StateTTL),
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// handleGothCallback completes the OAuth flow, validates the email domain if configured,
// and writes a signed session cookie on success.
func handleGothCallback(w http.ResponseWriter, r *http.Request, provider goth.Provider, cfg *alaye.OAuth, secret []byte) {
	cookie, err := r.Cookie(def.GothSessionCookie)
	if err != nil {
		http.Error(w, "Session expired or missing", http.StatusBadRequest)
		return
	}

	decodedSess, err := base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		http.Error(w, "Invalid cookie encoding", http.StatusBadRequest)
		return
	}

	sess, err := provider.UnmarshalSession(string(decodedSess))
	if err != nil {
		http.Error(w, "Invalid session data", http.StatusBadRequest)
		return
	}

	user, err := provider.FetchUser(sess)
	if err != nil {
		clearCookie(w, def.GothSessionCookie)

		params := r.URL.Query()
		if _, err := sess.Authorize(provider, params); err != nil {
			http.Error(w, "Authorization failed: "+err.Error(), http.StatusForbidden)
			return
		}

		user, err = provider.FetchUser(sess)
		if err != nil {
			http.Error(w, "Failed to fetch user: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if len(cfg.EmailDomains) > 0 {
		valid := false
		for _, domain := range cfg.EmailDomains {
			if strings.HasSuffix(strings.ToLower(user.Email), "@"+strings.ToLower(domain)) {
				valid = true
				break
			}
		}
		if !valid {
			clearCookie(w, def.GothSessionCookie)
			http.Error(w, "Email domain not allowed", http.StatusForbidden)
			return
		}
	}

	clearCookie(w, def.GothSessionCookie)

	// Resolve the session expiry. Prefer the IdP's ExpiresAt; fall back to the
	// configured SessionTTL (or the package default). Always take the sooner
	// of the two so neither the operator nor the IdP can be silently bypassed.
	sessionTTL := cfg.SessionTTL
	if sessionTTL <= 0 {
		sessionTTL = def.DefaultOAuthSessionTTL
	}
	configExpiry := time.Now().Add(sessionTTL)

	expiresAt := configExpiry
	if !user.ExpiresAt.IsZero() && user.ExpiresAt.Before(configExpiry) {
		expiresAt = user.ExpiresAt
	}

	signed := signSessionCookie(user.AccessToken, expiresAt, secret)

	http.SetCookie(w, &http.Cookie{
		Name:     def.SessionCookieName,
		Value:    signed,
		Path:     def.Slash,
		HttpOnly: true,
		Secure:   isSecure(r),
		Expires:  expiresAt,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, def.Slash, http.StatusFound)
}

// signSessionCookie returns "<base64(token)>.<expiry_unix>.<base64(hmac)>".
// The expiry (Unix seconds) is included inside the MAC so it cannot be
// tampered with independently of the signature.
func signSessionCookie(token string, expiresAt time.Time, secret []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(token))
	expiry := strconv.FormatInt(expiresAt.Unix(), 10)
	payload := encoded + cookieValueSeparator + expiry
	mac := computeHMAC(payload, secret)
	return payload + cookieValueSeparator + mac
}

// verifySessionCookie returns true only when the cookie carries a valid HMAC
// signature AND the embedded expiry has not passed.
//
// Cookie format: "<base64(token)>.<expiry_unix>.<base64(hmac)>"
//
// Expiry is verified first (cheap) then the HMAC (constant-time). Doing it
// this order is safe because a tampered expiry will fail the HMAC check — an
// attacker cannot extend a session by editing the timestamp alone.
func verifySessionCookie(value string, secret []byte) bool {
	// Locate the last "." — everything before it is the signed payload.
	idx := strings.LastIndex(value, cookieValueSeparator)
	if idx < 1 {
		return false
	}
	payload := value[:idx]
	gotMAC := value[idx+1:]

	// Payload must be "<base64(token)>.<expiry_unix>".
	// Locate the separator between token and expiry.
	sepIdx := strings.LastIndex(payload, cookieValueSeparator)
	if sepIdx < 1 {
		return false
	}
	expiryStr := payload[sepIdx+1:]
	expiryUnix, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil {
		return false
	}

	// Reject expired sessions before doing any cryptographic work.
	if time.Now().Unix() > expiryUnix {
		return false
	}

	// Constant-time HMAC comparison prevents timing attacks.
	wantMAC := computeHMAC(payload, secret)
	return hmac.Equal([]byte(gotMAC), []byte(wantMAC))
}

// computeHMAC returns the base64url-encoded HMAC-SHA256 of data under key.
func computeHMAC(data string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// isCallbackRequest returns true when the current request looks like an OAuth callback.
func isCallbackRequest(r *http.Request, redirectURL string) bool {
	return strings.Contains(redirectURL, r.URL.Path) && r.URL.Query().Get(def.CallBackCodeKey) != ""
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     def.Slash,
		MaxAge:   -1,
		HttpOnly: true,
	})
}

// generateState produces a cryptographically random state string for CSRF protection.
func generateState() (string, error) {
	b := make([]byte, def.DefaultByteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generateState: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// isSecure returns true when the request was received over TLS.
// X-Forwarded-Proto is intentionally not trusted here; proxy trust is handled
// at the IPManager layer before requests reach this middleware.
func isSecure(r *http.Request) bool {
	return r.TLS != nil
}
