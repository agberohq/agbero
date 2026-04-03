package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// Mocks

type MockProvider struct {
	goth.Provider
	Session *MockSession
}

func (m *MockProvider) Name() string { return "mock" }
func (m *MockProvider) BeginAuth(state string) (goth.Session, error) {
	return m.Session, nil
}
func (m *MockProvider) UnmarshalSession(data string) (goth.Session, error) {
	if data == "valid_session_data" {
		return m.Session, nil
	}
	return nil, errors.New("invalid session")
}
func (m *MockProvider) FetchUser(session goth.Session) (goth.User, error) {
	return goth.User{
		Email:       "test@example.com",
		AccessToken: "mock_token_123",
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}, nil
}
func (m *MockProvider) SetName(name string)                                     {}
func (m *MockProvider) Debug(debug bool)                                        {}
func (m *MockProvider) RefreshToken(refreshToken string) (*oauth2.Token, error) { return nil, nil }

type MockSession struct {
	AuthURL string
}

func (s *MockSession) GetAuthURL() (string, error) { return s.AuthURL, nil }
func (s *MockSession) Marshal() string             { return "valid_session_data" }
func (s *MockSession) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	return "mock_token_123", nil
}

// Helper to create a signed session cookie value matching signSessionCookie logic
func createSignedSessionCookie(token string, secret []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(token))
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(encoded))
	mac := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return encoded + cookieValueSeparator + mac
}

func TestOAuthMiddleware_Goth(t *testing.T) {
	mockProv := &MockProvider{
		Session: &MockSession{AuthURL: "http://provider.com/auth"},
	}

	secret := []byte("test-secret-key-for-testing-only")
	validSessionB64 := base64.StdEncoding.EncodeToString([]byte("valid_session_data"))

	t.Run("Start Goth Flow", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()

		startGothFlow(rec, req, mockProv)

		if rec.Code != http.StatusTemporaryRedirect {
			t.Errorf("Expected 307 redirect, got %d", rec.Code)
		}

		cookies := rec.Result().Cookies()
		found := false
		for _, c := range cookies {
			if c.Name == woos.GothSessionCookie && c.Value == validSessionB64 {
				found = true
				break
			}
		}
		if !found {
			t.Error("Goth session cookie not set correctly (expected base64 encoded)")
		}
	})

	t.Run("Handle Callback Active", func(t *testing.T) {
		cfg := &alaye.OAuth{
			Enabled:      alaye.Active,
			Provider:     "mock",
			EmailDomains: []string{"example.com"},
			RedirectURL:  "/callback",
		}

		req := httptest.NewRequest("GET", "/callback?code=123&state=xyz", nil)
		req.AddCookie(&http.Cookie{Name: woos.GothSessionCookie, Value: validSessionB64})

		rec := httptest.NewRecorder()

		handleGothCallback(rec, req, mockProv, cfg, secret)

		if rec.Code != http.StatusFound {
			t.Errorf("Expected 302 redirect, got %d. Body: %s", rec.Code, rec.Body.String())
		}

		cookies := rec.Result().Cookies()
		found := false
		for _, c := range cookies {
			if c.Name == woos.SessionCookieName {
				// Verify the cookie value is properly signed: <base64(token)>.<base64(hmac)>
				parts := strings.Split(c.Value, cookieValueSeparator)
				if len(parts) == 2 {
					// Decode the token part and verify it matches
					decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
					if err == nil && string(decoded) == "mock_token_123" {
						found = true
					}
				}
				break
			}
		}
		if !found {
			t.Error("Application session cookie not set with valid signed value")
		}
	})

	t.Run("Handle Callback Domain Unknown", func(t *testing.T) {
		cfg := &alaye.OAuth{
			Enabled:      alaye.Active,
			Provider:     "mock",
			EmailDomains: []string{"corp.com"},
			RedirectURL:  "/callback",
		}

		req := httptest.NewRequest("GET", "/callback?code=123&state=xyz", nil)
		req.AddCookie(&http.Cookie{Name: woos.GothSessionCookie, Value: validSessionB64})

		rec := httptest.NewRecorder()

		handleGothCallback(rec, req, mockProv, cfg, secret)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", rec.Code)
		}
	})
}
