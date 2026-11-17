package auth

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/olekukonko/ll"
	"golang.org/x/crypto/bcrypt"
)

var protectTestLogger = ll.New("test_protect").Disable()

func newProtectTestMiddleware(t *testing.T, path, title string) (func(http.Handler) http.Handler, string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &alaye.Protect{
		Enabled:    expect.Active,
		Title:      title,
		Users:      []string{"alice:" + string(hash)},
		SessionTTL: expect.Duration(time.Hour),
	}
	res := resource.New()
	t.Cleanup(res.Close)
	return Protect(cfg, path, res, protectTestLogger), string(hash)
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, ok := UserFromContext(r.Context()); ok {
			w.Header().Set("X-Test-User", user)
		}
		w.WriteHeader(http.StatusOK)
	})
}

func TestProtect_UnauthenticatedRedirectsToLogin(t *testing.T) {
	mw, _ := newProtectTestMiddleware(t, "/admin", "Admin")
	h := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/admin/_agbero/login?next=") {
		t.Fatalf("location = %q", loc)
	}
	if strings.Contains(loc, "evil") {
		t.Fatal("unsafe redirect target")
	}
}

func TestProtect_JSONRequestGets401(t *testing.T) {
	mw, _ := newProtectTestMiddleware(t, "/admin", "Admin")
	h := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate")
	}
}

func TestProtect_LoginFormEscapesTitleAndCSRF(t *testing.T) {
	mw, _ := newProtectTestMiddleware(t, "/admin", `<script>alert(1)</script>`)
	h := mw(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/admin/_agbero/login?next=https://evil.example", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("title was not HTML escaped")
	}
	if !strings.Contains(body, html.EscapeString(`<script>alert(1)</script>`)) {
		t.Fatal("escaped title missing")
	}
	if !strings.Contains(body, `name="csrf"`) {
		t.Fatal("CSRF field missing")
	}
	if strings.Contains(body, "https://evil.example") {
		t.Fatal("external next target was reflected")
	}
	if len(rec.Result().Cookies()) == 0 {
		t.Fatal("CSRF cookie missing")
	}
}

func loginForm(t *testing.T, h http.Handler, path string) (csrf, cookie string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login page status = %d", rec.Code)
	}
	re := regexp.MustCompile(`name="csrf" value="([^"]+)"`)
	m := re.FindStringSubmatch(rec.Body.String())
	if len(m) != 2 {
		t.Fatal("CSRF token not found")
	}
	for _, c := range rec.Result().Cookies() {
		if strings.HasSuffix(c.Name, "_csrf") {
			cookie = c.Name + "=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatal("CSRF cookie not found")
	}
	return m[1], cookie
}

func TestProtect_LoginSuccessAndSession(t *testing.T) {
	mw, _ := newProtectTestMiddleware(t, "/admin", "Admin")
	h := mw(okHandler())
	csrf, csrfCookie := loginForm(t, h, "/admin/_agbero/login?next=%2Fadmin")

	form := url.Values{"username": {"alice"}, "password": {"correct horse"}, "csrf": {csrf}, "next": {"/admin"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/_agbero/login?next=%2Fadmin", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", csrfCookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var session string
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "protect_session") && !strings.HasSuffix(c.Name, "_csrf") {
			session = c.Name + "=" + c.Value
		}
	}
	if session == "" {
		t.Fatal("session cookie not set")
	}

	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Cookie", session)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d", rec.Code)
	}
	if rec.Header().Get("X-Test-User") != "alice" {
		t.Fatalf("user context = %q", rec.Header().Get("X-Test-User"))
	}
}

func TestProtect_InvalidCSRFAndPassword(t *testing.T) {
	mw, _ := newProtectTestMiddleware(t, "/admin", "Admin")
	h := mw(okHandler())
	csrf, csrfCookie := loginForm(t, h, "/admin/_agbero/login")

	form := url.Values{"username": {"alice"}, "password": {"correct horse"}, "csrf": {"wrong"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/_agbero/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", csrfCookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("invalid CSRF status = %d, want 403", rec.Code)
	}

	form.Set("csrf", csrf)
	form.Set("password", "wrong")
	req = httptest.NewRequest(http.MethodPost, "/admin/_agbero/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", csrfCookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Invalid username or password") {
		t.Fatalf("invalid password response = %d", rec.Code)
	}
}

func TestProtect_TamperedCookieRejected(t *testing.T) {
	mw, _ := newProtectTestMiddleware(t, "/admin", "Admin")
	h := mw(okHandler())
	csrf, csrfCookie := loginForm(t, h, "/admin/_agbero/login")
	form := url.Values{"username": {"alice"}, "password": {"correct horse"}, "csrf": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/admin/_agbero/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", csrfCookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var session string
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "protect_session") && !strings.HasSuffix(c.Name, "_csrf") {
			session = c.Name + "=" + c.Value
		}
	}
	if session == "" {
		t.Fatal("no session cookie")
	}
	parts := strings.SplitN(session, "=", 2)
	if len(parts) != 2 || len(parts[1]) < 4 {
		t.Fatal("unexpected cookie")
	}
	tampered := parts[1][:len(parts[1])-1] + "x"
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Cookie", parts[0]+"="+tampered)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("tampered cookie status = %d, want redirect", rec.Code)
	}
}

func TestProtect_Logout(t *testing.T) {
	mw, _ := newProtectTestMiddleware(t, "/admin", "Admin")
	h := mw(okHandler())
	csrf, csrfCookie := loginForm(t, h, "/admin/_agbero/login")
	form := url.Values{"username": {"alice"}, "password": {"correct horse"}, "csrf": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/admin/_agbero/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", csrfCookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	session := ""
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "protect_session") && !strings.HasSuffix(c.Name, "_csrf") {
			session = c.Name + "=" + c.Value
		}
	}
	if session == "" {
		t.Fatal("no session")
	}
	// A fresh CSRF token is issued by the logout's login page; use the one
	// already present on the login form flow for this test.
	csrf, csrfCookie = loginForm(t, h, "/admin/_agbero/login")
	form = url.Values{"csrf": {csrf}}
	req = httptest.NewRequest(http.MethodPost, "/admin/_agbero/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", csrfCookie+"; "+session)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("logout status = %d", rec.Code)
	}
}

func TestProtect_DisabledPassesThrough(t *testing.T) {
	cfg := &alaye.Protect{Enabled: expect.Inactive}
	h := Protect(cfg, "/admin", resource.New(), protectTestLogger)(okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("disabled status = %d", rec.Code)
	}
}

func TestProtect_CookieScopedToRoute(t *testing.T) {
	mwAdmin, _ := newProtectTestMiddleware(t, "/admin", "Admin")
	mwPublic, _ := newProtectTestMiddleware(t, "/public", "Public")
	admin := mwAdmin(okHandler())
	public := mwPublic(okHandler())
	csrf, csrfCookie := loginForm(t, admin, "/admin/_agbero/login")
	form := url.Values{"username": {"alice"}, "password": {"correct horse"}, "csrf": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/admin/_agbero/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", csrfCookie)
	rec := httptest.NewRecorder()
	admin.ServeHTTP(rec, req)
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "protect_session") {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session")
	}
	req = httptest.NewRequest(http.MethodGet, "/public", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	public.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("cross-route cookie accepted: %d", rec.Code)
	}
}

func TestProtect_UnknownUserDoesNotRevealOrPanic(t *testing.T) {
	mw, _ := newProtectTestMiddleware(t, "/admin", "Admin")
	h := mw(okHandler())
	csrf, csrfCookie := loginForm(t, h, "/admin/_agbero/login")
	form := url.Values{"username": {"nobody"}, "password": {"whatever"}, "csrf": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/admin/_agbero/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", csrfCookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Invalid username or password") {
		t.Fatalf("unknown user response = %d %q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "nobody") {
		t.Fatal("username reflected into login error")
	}
}

func TestProtect_ExpiredSessionRejected(t *testing.T) {
	cfg := &alaye.Protect{
		Enabled: expect.Active,
		Users:   []string{"alice:hash"},
	}
	a, err := newProtect(cfg, "/admin", resource.New())
	if err != nil {
		t.Fatal(err)
	}
	token := a.signSession("alice", time.Now().Add(-time.Second))
	if _, ok := a.verifySession(token); ok {
		t.Fatal("expired session accepted")
	}
	token = a.signSession("alice", time.Now().Add(time.Hour))
	if user, ok := a.verifySession(token); !ok || user != "alice" {
		t.Fatalf("valid session rejected: %q %v", user, ok)
	}
}

func TestProtect_StripsOnlyItsCookieBeforeBackend(t *testing.T) {
	mw, _ := newProtectTestMiddleware(t, "/admin", "Admin")
	seen := ""
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}))
	csrf, csrfCookie := loginForm(t, h, "/admin/_agbero/login")
	form := url.Values{"username": {"alice"}, "password": {"correct horse"}, "csrf": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/admin/_agbero/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", csrfCookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if strings.Contains(c.Name, "protect_session") && !strings.HasSuffix(c.Name, "_csrf") {
			session = c
		}
	}
	if session == nil {
		t.Fatal("no session")
	}
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(session)
	req.AddCookie(&http.Cookie{Name: "app_session", Value: "keep-me"})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(seen, session.Name+"=") {
		t.Fatalf("auth cookie leaked upstream: %q", seen)
	}
	if !strings.Contains(seen, "app_session=keep-me") {
		t.Fatalf("unrelated cookie stripped: %q", seen)
	}
}
