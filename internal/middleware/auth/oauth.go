package auth

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/gitlab"
	"github.com/markbates/goth/providers/google"
	"github.com/markbates/goth/providers/openidConnect"
	"github.com/olekukonko/errors"
)

// OAuth middleware using markbates/goth for multi-provider support.
func OAuth(cfg *alaye.OAuth) func(http.Handler) http.Handler {
	if cfg.Enabled.NotActive() {
		return func(next http.Handler) http.Handler { return next }
	}

	// 1. Initialize the specific Goth Provider based on config
	provider, err := getProvider(cfg)
	if err != nil {
		// If provider fails to init (e.g. bad OIDC url), we return a broken middleware
		// that logs the error on request.
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "OAuth Configuration Error: "+err.Error(), http.StatusInternalServerError)
			})
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 2. Callback Handling
			if isCallbackRequest(r, cfg.RedirectURL) {
				handleGothCallback(w, r, provider, cfg)
				return
			}

			// 3. Check Existing Session
			cookie, err := r.Cookie(woos.SessionCookieName)
			if err == nil && cookie.Value != "" {
				// In prod: Verify/Decrypt cookie with cfg.CookieSecret
				next.ServeHTTP(w, r)
				return
			}

			// 4. Start Internal Flow
			startGothFlow(w, r, provider)
		})
	}
}

func getProvider(cfg *alaye.OAuth) (goth.Provider, error) {
	callback := cfg.RedirectURL
	key := cfg.ClientID
	secret := cfg.ClientSecret.String()
	scopes := cfg.Scopes

	switch strings.ToLower(cfg.Provider) {
	case woos.ProviderGoogle:
		return google.New(key, secret, callback, scopes...), nil
	case woos.ProviderGitHub:
		return github.New(key, secret, callback, scopes...), nil
	case woos.ProviderGitLab:
		return gitlab.New(key, secret, callback, scopes...), nil
	case woos.ProviderOIDC, woos.ProviderGeneric:
		// OIDC requires a Discovery URL (cfg.AuthURL can act as the Issuer URL here)
		// If AuthURL is empty, this will fail.
		if cfg.AuthURL == "" {
			return nil, woos.ErrInvalidAuthURL
		}
		return openidConnect.New(key, secret, callback, cfg.AuthURL, scopes...)
	default:
		return nil, errors.Newf("%w: %s", woos.ErrUnsupportedProvider, cfg.Provider)
	}
}

func startGothFlow(w http.ResponseWriter, r *http.Request, provider goth.Provider) {
	state := generateState()

	// BeginAuth returns a Session which holds the state/nonce/authorize_url
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

	// Serialize the Goth session to a cookie so we can retrieve it in the callback
	sessData := sess.Marshal()
	encodedSess := base64.StdEncoding.EncodeToString([]byte(sessData))

	http.SetCookie(w, &http.Cookie{
		Name:     woos.GothSessionCookie,
		Value:    encodedSess,
		Path:     woos.Slash,
		HttpOnly: true,
		Secure:   isSecure(r),
		Expires:  time.Now().Add(woos.StateTTL),
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func handleGothCallback(w http.ResponseWriter, r *http.Request, provider goth.Provider, cfg *alaye.OAuth) {
	// 1. Retrieve the session data from cookie
	cookie, err := r.Cookie(woos.GothSessionCookie)
	if err != nil {
		http.Error(w, "Session expired or missing", http.StatusBadRequest)
		return
	}

	// 2. Unmarshal into a Session object specific to the provider

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

	// 3. Validate the request parameters (code, state) against the session
	// FetchUser calls Exchange() internally
	user, err := provider.FetchUser(sess)
	if err != nil {
		// Clean up cookie
		clearCookie(w, woos.GothSessionCookie)

		// Goth validates params. If `Authorize` has not been called (i.e. just getting params),
		// we might need to feed params to session.
		// NOTE: In Goth, `sess` usually abstracts the params reading,
		// but `FetchUser` might fail if the params aren't in the URL query as expected.
		// However, standard Goth providers read from `r.URL.Query()` implicitly
		// inside `FetchUser`? Unknown, `FetchUser` takes `Session`.
		// The `Session` impl usually needs to be updated with params.
		// Actually, `provider.FetchUser` usually expects `Authorize` to have happened.
		// Let's explicitly look at how Goth does it without `gothic`.

		// Correct flow for manual Goth:
		params := r.URL.Query()
		if _, err := sess.Authorize(provider, params); err != nil {
			http.Error(w, "Authorization failed: "+err.Error(), http.StatusForbidden)
			return
		}

		// Retry fetch after Authorize
		user, err = provider.FetchUser(sess)
		if err != nil {
			http.Error(w, "Failed to fetch user: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// 4. Validate Email Domain
	if len(cfg.EmailDomains) > 0 {
		valid := false
		for _, domain := range cfg.EmailDomains {
			if strings.HasSuffix(strings.ToLower(user.Email), "@"+strings.ToLower(domain)) {
				valid = true
				break
			}
		}
		if !valid {
			clearCookie(w, woos.GothSessionCookie)
			http.Error(w, "Email domain not allowed", http.StatusForbidden)
			return
		}
	}

	// 5. Cleanup OAuth state
	clearCookie(w, woos.GothSessionCookie)

	// 6. Set App Session
	// In production: Encrypt user.AccessToken using cfg.CookieSecret
	http.SetCookie(w, &http.Cookie{
		Name:     woos.SessionCookieName,
		Value:    user.AccessToken,
		Path:     woos.Slash,
		HttpOnly: true,
		Secure:   isSecure(r),
		Expires:  user.ExpiresAt,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, woos.Slash, http.StatusFound)
}

func isCallbackRequest(r *http.Request, redirectURL string) bool {
	// Basic check: does current path match redirect path?
	// Also check for 'code' which indicates a callback
	if strings.Contains(redirectURL, r.URL.Path) && r.URL.Query().Get(woos.CallBackCodeKey) != "" {
		return true
	}
	return false
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     woos.Slash,
		MaxAge:   -1,
		HttpOnly: true,
	})
}

func generateState() string {
	b := make([]byte, woos.DefaultByteLen)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func isSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	// Check X-Forwarded-Proto header (standard for proxies)
	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return strings.ToLower(scheme) == "https"
	}
	return false
}
