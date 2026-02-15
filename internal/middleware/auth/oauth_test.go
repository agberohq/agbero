package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// --- Mocks ---

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

// --- Tests ---

func TestOAuthMiddleware_Goth(t *testing.T) {
	// Setup Mock Provider
	mockProv := &MockProvider{
		Session: &MockSession{AuthURL: "http://provider.com/auth"},
	}

	// Override the getProvider function behavior by wrapping OAuth or
	// slightly modifying OAuth implementation to accept a provider injector for testing.
	// Since we can't easily inject into the closure without changing the signature,
	// we will manually test the logic flow functions (startGothFlow, handleGothCallback)
	// or perform an integration test with a "generic" provider config that fails
	// but verify logic before that.

	// Better approach for unit test: Test the helper functions directly
	// since we want to verify OUR logic, not Goth's internal logic.

	t.Run("Start Goth Flow", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()

		startGothFlow(rec, req, mockProv)

		if rec.Code != http.StatusTemporaryRedirect {
			t.Errorf("Expected 307 redirect, got %d", rec.Code)
		}

		// Verify Cookie set
		cookies := rec.Result().Cookies()
		found := false
		for _, c := range cookies {
			if c.Name == woos.GothSessionCookie && c.Value == "valid_session_data" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Goth session cookie not set correctly")
		}
	})

	t.Run("Handle Callback Active", func(t *testing.T) {
		cfg := &alaye.OAuth{
			Provider:     "mock",
			EmailDomains: []string{"example.com"},
		}

		req := httptest.NewRequest("GET", "/callback?code=123&state=xyz", nil)
		// Inject the cookie that startGothFlow would have set
		req.AddCookie(&http.Cookie{Name: woos.GothSessionCookie, Value: "valid_session_data"})

		rec := httptest.NewRecorder()

		handleGothCallback(rec, req, mockProv, cfg)

		if rec.Code != http.StatusFound {
			t.Errorf("Expected 302 redirect, got %d", rec.Code)
		}

		// Verify App Session Cookie
		cookies := rec.Result().Cookies()
		found := false
		for _, c := range cookies {
			if c.Name == woos.SessionCookieName && c.Value == "mock_token_123" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Application session cookie not set")
		}
	})

	t.Run("Handle Callback Domain Unknown", func(t *testing.T) {
		cfg := &alaye.OAuth{
			Provider:     "mock",
			EmailDomains: []string{"corp.com"}, // Mock returns example.com
		}

		req := httptest.NewRequest("GET", "/callback?code=123", nil)
		req.AddCookie(&http.Cookie{Name: woos.GothSessionCookie, Value: "valid_session_data"})

		rec := httptest.NewRecorder()

		handleGothCallback(rec, req, mockProv, cfg)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", rec.Code)
		}
	})
}
