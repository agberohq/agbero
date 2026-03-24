package agbero

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// newTestServer builds a minimal Server suitable for unit-testing admin handlers.
// It initialises jtiStore and jtiLifetime so token revocation tests work correctly.
func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	tmpDir := t.TempDir()
	hostsDir := filepath.Join(tmpDir, "hosts")
	if err := os.MkdirAll(hostsDir, woos.DirPerm); err != nil {
		t.Fatal(err)
	}

	s := NewServer(
		WithHostManager(discovery.NewHost(woos.NewFolder(hostsDir), discovery.WithLogger(testLogger))),
		WithGlobalConfig(&alaye.Global{
			Storage: alaye.Storage{HostsDir: hostsDir},
		}),
		WithLogger(testLogger),
	)
	return s, hostsDir
}

// signedToken mints a JWT with the given issuer and secret for use in test requests.
func signedToken(t *testing.T, secret, issuer, jti string, ttl time.Duration) string {
	t.Helper()
	now := time.Now()
	claims := &adminClaims{
		User: "testuser",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("signedToken: %v", err)
	}
	return signed
}

// bcryptEntry builds a "username:bcrypt-hash" entry for BasicAuth users slice.
func bcryptEntry(t *testing.T, username, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcryptEntry: %v", err)
	}
	return fmt.Sprintf("%s:%s", username, string(hash))
}

// validHostPayload returns a minimal JSON body accepted by POST /api/hosts.
func validHostPayload(domain, backendAddr string) []byte {
	body := fmt.Sprintf(`{
		"domain": %q,
		"config": {
			"domains": [%q],
			"routes": [{
				"path": "/",
				"backends": {
					"servers": [{"address": %q}]
				}
			}]
		}
	}`, domain, domain, backendAddr)
	return []byte(body)
}

// TestAdmin_HealthEndpoint checks that /healthz returns 200 without auth.
func TestAdmin_HealthEndpoint(t *testing.T) {
	s, _ := newTestServer(t)

	mux := http.NewServeMux()
	s.registerAdminHealthEndpoint(mux)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != "OK" {
		t.Errorf("expected body OK, got %q", rec.Body.String())
	}
}

// TestAdmin_Login_MissingConfig verifies login returns 403 when BasicAuth is not configured.
func TestAdmin_Login_MissingConfig(t *testing.T) {
	s, _ := newTestServer(t)

	body := `{"username":"admin","password":"secret"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.handleLogin(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

// TestAdmin_Login_InvalidCredentials verifies that wrong credentials return 401.
func TestAdmin_Login_InvalidCredentials(t *testing.T) {
	s, _ := newTestServer(t)
	s.global.Admin.BasicAuth.Enabled = alaye.Active
	s.global.Admin.BasicAuth.Users = []string{bcryptEntry(t, "admin", "correct-password")}
	s.global.Admin.JWTAuth.Enabled = alaye.Active
	s.global.Admin.JWTAuth.Secret = "test-secret-key-32-bytes-minimum!"

	body := `{"username":"admin","password":"wrong-password"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.handleLogin(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

// TestAdmin_Login_Success verifies that correct credentials return a JWT with the right issuer.
func TestAdmin_Login_Success(t *testing.T) {
	s, _ := newTestServer(t)
	secret := "test-secret-key-32-bytes-minimum!"
	s.global.Admin.BasicAuth.Enabled = alaye.Active
	s.global.Admin.BasicAuth.Users = []string{bcryptEntry(t, "admin", "correct-password")}
	s.global.Admin.JWTAuth.Enabled = alaye.Active
	s.global.Admin.JWTAuth.Secret = alaye.Value(secret)

	body := `{"username":"admin","password":"correct-password"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.handleLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	tokenStr, ok := resp["token"]
	if !ok || tokenStr == "" {
		t.Fatal("response missing token field")
	}

	tok, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		return []byte(secret), nil
	})
	if err != nil || !tok.Valid {
		t.Fatalf("token invalid: %v", err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("claims not MapClaims")
	}
	if iss, _ := claims.GetIssuer(); iss != woos.AdminTokenIssuer {
		t.Errorf("expected issuer %q, got %q", woos.AdminTokenIssuer, iss)
	}
	if jti, _ := claims["jti"].(string); jti == "" {
		t.Error("token missing jti claim")
	}
}

// TestAdmin_Login_TokenTTL verifies the issued token respects the reduced 8h TTL.
func TestAdmin_Login_TokenTTL(t *testing.T) {
	s, _ := newTestServer(t)
	secret := "test-secret-key-32-bytes-minimum!"
	s.global.Admin.BasicAuth.Enabled = alaye.Active
	s.global.Admin.BasicAuth.Users = []string{bcryptEntry(t, "admin", "pass")}
	s.global.Admin.JWTAuth.Enabled = alaye.Active
	s.global.Admin.JWTAuth.Secret = alaye.Value(secret)

	body := `{"username":"admin","password":"pass"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleLogin(rec, req)

	var resp map[string]string
	json.NewDecoder(rec.Body).Decode(&resp)

	tok, _ := jwt.Parse(resp["token"], func(t *jwt.Token) (any, error) { return []byte(secret), nil })
	claims := tok.Claims.(jwt.MapClaims)
	exp, _ := claims.GetExpirationTime()
	iat, _ := claims.GetIssuedAt()

	ttl := exp.Time.Sub(iat.Time)
	if ttl > woos.AdminTokenTTL+time.Second {
		t.Errorf("token TTL %v exceeds configured AdminTokenTTL %v", ttl, woos.AdminTokenTTL)
	}
}

// TestAdmin_Logout_RevokesToken verifies that logging out adds the JTI to the revocation store.
func TestAdmin_Logout_RevokesToken(t *testing.T) {
	s, _ := newTestServer(t)
	secret := "test-secret-key-32-bytes-minimum!"
	s.global.Admin.JWTAuth.Enabled = alaye.Active
	s.global.Admin.JWTAuth.Secret = alaye.Value(secret)

	tokenStr := signedToken(t, secret, woos.AdminTokenIssuer, "test-jti-001", time.Hour)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set(woos.AuthorizationHeaderKey, woos.HeaderKeyBearer+" "+tokenStr)
	rec := httptest.NewRecorder()

	s.handleLogout(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if !s.jtiStore.Has("test-jti-001") {
		t.Error("JTI not found in revocation store after logout")
	}
}

// TestAdmin_Logout_NoToken verifies that logout with no token returns 200 without error.
func TestAdmin_Logout_NoToken(t *testing.T) {
	s, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	rec := httptest.NewRecorder()
	s.handleLogout(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// TestAdmin_JWT_IssuerEnforced verifies that buildAuthMiddleware always sets issuer
// to woos.AdminTokenIssuer, rejecting tokens with a different issuer even if the
// signature is valid.
func TestAdmin_JWT_IssuerEnforced(t *testing.T) {
	s, _ := newTestServer(t)
	secret := "test-secret-key-32-bytes-minimum!"
	s.global.Admin.JWTAuth.Enabled = alaye.Active
	s.global.Admin.JWTAuth.Secret = alaye.Value(secret)
	s.global.Admin.JWTAuth.Issuer = ""

	wrongIssuerToken := signedToken(t, secret, "other-service", "jti-wrong-iss", time.Hour)

	protected := s.buildAuthMiddleware(s.global.Admin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set(woos.AuthorizationHeaderKey, woos.HeaderKeyBearer+" "+wrongIssuerToken)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for wrong issuer, got %d", rec.Code)
	}
}

// TestAdmin_JWT_CorrectIssuerAccepted verifies tokens with the correct admin issuer pass.
func TestAdmin_JWT_CorrectIssuerAccepted(t *testing.T) {
	s, _ := newTestServer(t)
	secret := "test-secret-key-32-bytes-minimum!"
	s.global.Admin.JWTAuth.Enabled = alaye.Active
	s.global.Admin.JWTAuth.Secret = alaye.Value(secret)

	validToken := signedToken(t, secret, woos.AdminTokenIssuer, "jti-valid", time.Hour)

	protected := s.buildAuthMiddleware(s.global.Admin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set(woos.AuthorizationHeaderKey, woos.HeaderKeyBearer+" "+validToken)
	rec := httptest.NewRecorder()
	protected.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for correct issuer, got %d", rec.Code)
	}
}

// TestAdmin_HostsAPI_Add verifies that POST /api/hosts adds a host to the host manager.
func TestAdmin_HostsAPI_Add(t *testing.T) {
	s, hostsDir := newTestServer(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	_ = hostsDir

	payload := validHostPayload("test.example.com", backend.URL)
	req := httptest.NewRequest(http.MethodPost, "/api/hosts", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.handleHostsAPI(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}

	h := s.hostManager.Get("test.example.com")
	if h == nil {
		t.Error("host not found in host manager after POST")
	}
}

// TestAdmin_HostsAPI_MissingDomain verifies that POST without a domain returns 400.
func TestAdmin_HostsAPI_MissingDomain(t *testing.T) {
	s, _ := newTestServer(t)

	payload := []byte(`{"config": {"routes": []}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/hosts", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.handleHostsAPI(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// TestAdmin_HostsAPI_TraversalRejected verifies that domain values with path traversal are rejected.
func TestAdmin_HostsAPI_TraversalRejected(t *testing.T) {
	s, _ := newTestServer(t)

	for _, badDomain := range []string{"../etc/passwd", "foo/bar", "foo\\bar"} {
		payload := []byte(fmt.Sprintf(`{"domain":%q,"config":{"routes":[]}}`, badDomain))
		req := httptest.NewRequest(http.MethodPost, "/api/hosts", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.handleHostsAPI(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("domain %q: expected 400, got %d", badDomain, rec.Code)
		}
	}
}

// TestAdmin_HostsAPI_Delete verifies that DELETE /api/hosts removes a host from the host manager.
func TestAdmin_HostsAPI_Delete(t *testing.T) {
	s, hostsDir := newTestServer(t)

	hostFile := filepath.Join(hostsDir, "delete.example.com.hcl")
	if err := os.WriteFile(hostFile, []byte(`domains = ["delete.example.com"]
route "/" {
  backend {
    server {
      address = "http://127.0.0.1:9999"
    }
  }
}
`), woos.FilePerm); err != nil {
		t.Fatal(err)
	}
	if err := s.hostManager.ReloadFull(); err != nil {
		t.Fatal(err)
	}

	if s.hostManager.Get("delete.example.com") == nil {
		t.Fatal("host not loaded before delete test")
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/hosts?domain=delete.example.com", nil)
	rec := httptest.NewRecorder()
	s.handleHostsAPI(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", rec.Code, rec.Body.String())
	}
	if s.hostManager.Get("delete.example.com") != nil {
		t.Error("host still present after DELETE")
	}
	if _, err := os.Stat(hostFile); !os.IsNotExist(err) {
		t.Error("host file still on disk after DELETE")
	}
}

// TestAdmin_HostsAPI_DeleteMissingDomain verifies DELETE without domain returns 400.
func TestAdmin_HostsAPI_DeleteMissingDomain(t *testing.T) {
	s, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/hosts", nil)
	rec := httptest.NewRecorder()
	s.handleHostsAPI(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// TestAdmin_HostsAPI_ProtectedHost verifies that protected hosts cannot be modified via API.
func TestAdmin_HostsAPI_ProtectedHost(t *testing.T) {
	s, _ := newTestServer(t)

	protectedHost := &alaye.Host{
		Protected: alaye.Active,
		Domains:   []string{"protected.example.com"},
	}
	s.hostManager.Set("protected.example.com", protectedHost)

	req := httptest.NewRequest(http.MethodDelete, "/api/hosts?domain=protected.example.com", nil)
	rec := httptest.NewRecorder()
	s.handleHostsAPI(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for protected host, got %d", rec.Code)
	}
}

// TestAdmin_HostsAPI_MethodNotAllowed verifies unsupported methods return 405.
func TestAdmin_HostsAPI_MethodNotAllowed(t *testing.T) {
	s, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodPatch, "/api/hosts", nil)
	rec := httptest.NewRecorder()
	s.handleHostsAPI(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

// TestAdmin_SecurityHeaders verifies that wrapAdminMiddleware injects required security headers.
func TestAdmin_SecurityHeaders(t *testing.T) {
	s, _ := newTestServer(t)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := s.wrapAdminMiddleware(inner, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	headers := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}
	for header, expected := range headers {
		if got := rec.Header().Get(header); got != expected {
			t.Errorf("header %s: expected %q, got %q", header, expected, got)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy header missing")
	}
}

// TestAdmin_isValidIPOrCIDR tests the IP/CIDR validation helper.
func TestAdmin_isValidIPOrCIDR(t *testing.T) {
	cases := []struct {
		input string
		valid bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.0/8", true},
		{"::1", true},
		{"2001:db8::/32", true},
		{"not-an-ip", false},
		{"", false},
		{"999.999.999.999", false},
	}
	for _, c := range cases {
		got := isValidIPOrCIDR(c.input)
		if got != c.valid {
			t.Errorf("isValidIPOrCIDR(%q) = %v, want %v", c.input, got, c.valid)
		}
	}
}

// TestAdmin_verifyCredentials tests the timing-safe credential verification.
func TestAdmin_verifyCredentials(t *testing.T) {
	s, _ := newTestServer(t)

	users := []string{bcryptEntry(t, "admin", "correct")}

	if !s.verifyCredentials(users, "admin", "correct") {
		t.Error("valid credentials rejected")
	}
	if s.verifyCredentials(users, "admin", "wrong") {
		t.Error("wrong password accepted")
	}
	if s.verifyCredentials(users, "nobody", "correct") {
		t.Error("unknown user accepted")
	}
	if s.verifyCredentials([]string{}, "admin", "correct") {
		t.Error("empty users accepted")
	}
}

// TestAdmin_ConfigDump_MasksSecrets verifies that /config never leaks sensitive values.
func TestAdmin_ConfigDump_MasksSecrets(t *testing.T) {
	s, _ := newTestServer(t)
	s.global.Gossip.Enabled = alaye.Active
	s.global.Gossip.SecretKey = "super-secret-gossip-key"
	s.global.Admin.Enabled = alaye.Active
	s.global.Admin.JWTAuth.Enabled = alaye.Active
	s.global.Admin.JWTAuth.Secret = "jwt-secret-value"
	s.global.Admin.BasicAuth.Enabled = alaye.Active
	s.global.Admin.BasicAuth.Users = []string{"admin:bcrypt-hash"}
	s.global.Security.Enabled = alaye.Active
	s.global.Security.InternalAuthKey = "/path/to/key.pem"
	s.global.Storage.WorkDir = "/var/agbero/work"
	s.global.Storage.HostsDir = "/var/agbero/hosts"

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	rec := httptest.NewRecorder()
	s.handleConfigDump(rec, req)

	body := rec.Body.String()

	for _, secret := range []string{
		"super-secret-gossip-key",
		"jwt-secret-value",
		"bcrypt-hash",
		"/path/to/key.pem",
		"/var/agbero/work",
		"/var/agbero/hosts",
	} {
		if strings.Contains(body, secret) {
			t.Errorf("config dump contains secret value %q", secret)
		}
	}
}
