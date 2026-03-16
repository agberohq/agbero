package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/olekukonko/ll"
	"golang.org/x/crypto/bcrypt"
)

var (
	testLoggerBasic = ll.New("test_basic").Disable()
)

func TestBasic_SuccessHashed(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	cfg := &alaye.BasicAuth{
		Enabled: alaye.Active,
		Users:   []string{"user:" + string(hash)},
	}

	handler := Basic(cfg, testLoggerBasic)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("user", "pass")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// TestBasic_PlaintextPasswordRejected verifies that storing a plaintext password
// in the users list is rejected with 401 — only bcrypt hashes are accepted.
func TestBasic_PlaintextPasswordRejected(t *testing.T) {
	cfg := &alaye.BasicAuth{
		Enabled: alaye.Active,
		Users:   []string{"user:pass"},
	}

	handler := Basic(cfg, testLoggerBasic)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("user", "pass")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for plaintext password, got %d", w.Code)
	}
}

func TestBasic_InvalidPassword(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	cfg := &alaye.BasicAuth{
		Enabled: alaye.Active,
		Users:   []string{"user:" + string(hash)},
	}

	handler := Basic(cfg, testLoggerBasic)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("user", "wrong")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestBasic_NoAuthHeader(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	cfg := &alaye.BasicAuth{
		Enabled: alaye.Active,
		Users:   []string{"user:" + string(hash)},
	}

	handler := Basic(cfg, testLoggerBasic)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate header")
	}
}

func TestBasic_InvalidUser(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pass"), bcrypt.DefaultCost)
	cfg := &alaye.BasicAuth{
		Enabled: alaye.Active,
		Users:   []string{"user:" + string(hash)},
	}

	handler := Basic(cfg, testLoggerBasic)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("wronguser", "pass")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestBasic_DisabledPassesThrough(t *testing.T) {
	cfg := &alaye.BasicAuth{
		Enabled: alaye.Inactive,
	}

	reached := false
	handler := Basic(cfg, testLoggerBasic)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if !reached {
		t.Error("expected next handler to be called when basic auth is disabled")
	}
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}
