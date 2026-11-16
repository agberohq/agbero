package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/operation"
	"github.com/olekukonko/ll"
	"golang.org/x/crypto/bcrypt"
)

const protectAuthMaxFormBytes = 64 << 10

// protectLoginTemplate is the embedded route-local login page. Parsing happens
// once at package init; html/template handles all contextual escaping.
var protectLoginTemplate = template.Must(template.New("agbero-login").Parse(string(operation.LoginPage)))

type protectLoginPageData struct {
	Title  string
	Action string
	Next   string
	CSRF   string
	Error  string
}

// protectAuth implements the route-local login form and signed session cookie.
//
// The cookie contains only a username and expiry. It is signed with a
// per-process key, scoped to the route path, and never contains a password or
// bcrypt hash. A password change in the config invalidates the credentials but
// existing cookies remain valid until expiry; use short session_ttl values
// where that matters.
type protectAuth struct {
	cfg        *alaye.Protect
	routePath  string
	loginPath  string
	logoutPath string
	cookieName string
	csrfName   string
	key        []byte
	ttl        time.Duration
	users      map[string][]byte
	dummyHash  []byte
	title      string
	logger     *ll.Logger
}

// Protect returns middleware that requires a route-local login session.
func Protect(cfg *alaye.Protect, routePath string, res *resource.Resource, logger *ll.Logger) func(http.Handler) http.Handler {
	if cfg == nil || cfg.Enabled.NotActive() {
		return func(next http.Handler) http.Handler { return next }
	}

	a, err := newProtect(cfg, routePath, res)
	if err != nil {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "protect configuration error", http.StatusInternalServerError)
			})
		}
	}
	a.logger = logger
	return a.middleware
}

func newProtect(cfg *alaye.Protect, routePath string, res *resource.Resource) (*protectAuth, error) {
	routePath = normalizeAuthRoutePath(routePath)
	if routePath == "" || strings.Contains(routePath, "*") {
		return nil, fmt.Errorf("protect requires a concrete route path")
	}

	path := routePath
	if path == "/" {
		path = ""
	}
	loginPath := path + "/" + def.ProtectPathSeg + "/login"
	logoutPath := path + "/" + def.ProtectPathSeg + "/logout"

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("protect random key: %w", err)
	}
	dummy, err := bcrypt.GenerateFromPassword([]byte(def.DummyPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("protect dummy hash: %w", err)
	}

	users, err := resolveAgberoUsers(cfg.Users)
	if err != nil {
		return nil, err
	}
	cookieName := strings.TrimSpace(cfg.CookieName)
	if cookieName == "" {
		sum := sha256.Sum256([]byte(routePath))
		cookieName = def.ProtectCookieName + "_" + base64.RawURLEncoding.EncodeToString(sum[:8])
	}

	ttl := cfg.SessionTTL.StdDuration()
	if ttl <= 0 {
		ttl = def.ProtectSessionTTL
	}
	title := strings.TrimSpace(cfg.Title)
	if title == "" {
		title = "Protected area"
	}

	return &protectAuth{
		cfg:        cfg,
		routePath:  routePath,
		loginPath:  loginPath,
		logoutPath: logoutPath,
		cookieName: cookieName,
		csrfName:   cookieName + "_csrf",
		key:        key,
		ttl:        ttl,
		users:      users,
		dummyHash:  dummy,
		title:      title,
	}, nil
}

func normalizeAuthRoutePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if p != "/" {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

func resolveAgberoUsers(entries []string) (map[string][]byte, error) {
	users := make(map[string][]byte, len(entries))
	for i, entry := range entries {
		username, secret, ok := strings.Cut(strings.TrimSpace(entry), ":")
		username = strings.TrimSpace(username)
		if !ok || username == "" || strings.TrimSpace(secret) == "" {
			return nil, fmt.Errorf("protect users[%d]: must be username:bcrypt-hash", i)
		}
		rawSecret := strings.TrimSpace(secret)
		hash := rawSecret
		// Only resolve explicit secret-store references. A bcrypt hash itself
		// contains "$" characters, so running it through the generic Value
		// resolver would corrupt it via os.Expand.
		if expect.Value(rawSecret).IsSecretStoreRef() {
			resolved, err := expect.Value(rawSecret).ResolveErr(os.Getenv)
			if err != nil {
				return nil, fmt.Errorf("protect users[%d]: resolve secret: %w", i, err)
			}
			hash = resolved
		}
		if _, exists := users[username]; exists {
			return nil, fmt.Errorf("protect users[%d]: duplicate username %q", i, username)
		}
		users[username] = []byte(hash)
	}
	return users, nil
}

func (a *protectAuth) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Login/logout are the only unauthenticated endpoints. They live under
		// the route so the normal route matcher reaches this middleware.
		switch {
		case r.URL.Path == a.loginPath:
			a.handleLogin(w, r)
			return
		case r.URL.Path == a.logoutPath:
			a.handleLogout(w, r)
			return
		}

		user, ok := a.sessionUser(r)
		if !ok {
			a.challenge(w, r)
			return
		}
		// The backend is allowed to see other cookies, but never the Agbero
		// session cookie.
		stripCookie(r, a.cookieName)
		ctx := context.WithValue(r.Context(), authUserCtxKey{}, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type authUserCtxKey struct{}

// UserFromContext returns the authenticated route user, if any.
func UserFromContext(ctx context.Context) (string, bool) {
	u, ok := ctx.Value(authUserCtxKey{}).(string)
	return u, ok
}

func (a *protectAuth) challenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("WWW-Authenticate", `Agbero realm="`+a.title+`"`)
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"authentication required"}`))
		return
	}
	next := safeNext(r.URL.RequestURI(), a.routePath)
	target := a.loginPath + "?next=" + url.QueryEscape(next)
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (a *protectAuth) handleLogin(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"), a.routePath)
	if _, ok := a.sessionUser(r); ok {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")

	switch r.Method {
	case http.MethodGet:
		a.renderLogin(w, r, next, "")
	case http.MethodPost:
		a.handleLoginPost(w, r, next)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (a *protectAuth) handleLoginPost(w http.ResponseWriter, r *http.Request, next string) {
	r.Body = http.MaxBytesReader(w, r.Body, protectAuthMaxFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "Invalid origin", http.StatusForbidden)
		return
	}
	if !a.validCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	next = safeNext(r.FormValue("next"), next)

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	hash, exists := a.users[username]
	if !exists {
		hash = a.dummyHash
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil || !exists {
		a.renderLogin(w, r, next, "Invalid username or password")
		return
	}

	expires := time.Now().Add(a.ttl)
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookieName,
		Value:    a.signSession(username, expires),
		Path:     a.cookiePath(),
		HttpOnly: true,
		Secure:   isSecure(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
		MaxAge:   int(a.ttl.Seconds()),
	})
	clearCookieWithPath(w, a.csrfName, a.loginPath)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (a *protectAuth) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "Invalid origin", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil || !a.validCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	clearCookieWithPath(w, a.cookieName, a.cookiePath())
	clearCookieWithPath(w, a.csrfName, a.loginPath)
	http.Redirect(w, r, a.loginPath, http.StatusSeeOther)
}

func (a *protectAuth) renderLogin(w http.ResponseWriter, r *http.Request, next, errMsg string) {
	csrf, err := a.newCSRF(w, r)
	if err != nil {
		http.Error(w, "Unable to start login", http.StatusInternalServerError)
		return
	}
	action := a.loginPath + "?next=" + url.QueryEscape(next)
	var page bytes.Buffer
	if err := protectLoginTemplate.Execute(&page, protectLoginPageData{
		Title:  a.title,
		Action: action,
		Next:   next,
		CSRF:   csrf,
		Error:  errMsg,
	}); err != nil {
		http.Error(w, "Unable to render login", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(page.Bytes())
}

func (a *protectAuth) newCSRF(w http.ResponseWriter, r *http.Request) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name:     a.csrfName,
		Value:    token,
		Path:     a.loginPath,
		HttpOnly: true,
		Secure:   isSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	return token, nil
}

func (a *protectAuth) validCSRF(r *http.Request) bool {
	c, err := r.Cookie(a.csrfName)
	if err != nil || c.Value == "" {
		return false
	}
	got := r.FormValue("csrf")
	return subtle.ConstantTimeCompare([]byte(got), []byte(c.Value)) == 1
}

func (a *protectAuth) cookiePath() string { return a.routePath }

func (a *protectAuth) signSession(username string, expires time.Time) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(username)) + "." + strconv.FormatInt(expires.Unix(), 10)
	mac := hmac.New(sha256.New, a.key)
	_, _ = mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *protectAuth) sessionUser(r *http.Request) (string, bool) {
	c, err := r.Cookie(a.cookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return a.verifySession(c.Value)
}

func (a *protectAuth) verifySession(value string) (string, bool) {
	last := strings.LastIndexByte(value, '.')
	if last <= 0 {
		return "", false
	}
	payload, gotMAC := value[:last], value[last+1:]
	mac := hmac.New(sha256.New, a.key)
	_, _ = mac.Write([]byte(payload))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(gotMAC), []byte(want)) != 1 {
		return "", false
	}
	sep := strings.LastIndexByte(payload, '.')
	if sep <= 0 {
		return "", false
	}
	expiry, err := strconv.ParseInt(payload[sep+1:], 10, 64)
	if err != nil || time.Now().Unix() > expiry {
		return "", false
	}
	rawUser, err := base64.RawURLEncoding.DecodeString(payload[:sep])
	if err != nil {
		return "", false
	}
	username := string(rawUser)
	if _, exists := a.users[username]; !exists {
		return "", false
	}
	return username, true
}

func safeNext(raw, fallback string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.ContainsAny(raw, "\r\n") {
		return fallback
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.IsAbs() || u.Host != "" {
		return fallback
	}
	return raw
}

func sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func wantsJSON(r *http.Request) bool {
	if strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json") {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest")
}

func stripCookie(r *http.Request, name string) {
	values := r.Cookies()
	if len(values) == 0 {
		return
	}
	kept := make([]string, 0, len(values))
	for _, c := range values {
		if c.Name != name {
			kept = append(kept, c.Name+"="+c.Value)
		}
	}
	if len(kept) == 0 {
		r.Header.Del("Cookie")
		return
	}
	r.Header.Set("Cookie", strings.Join(kept, "; "))
}

func clearCookieWithPath(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
