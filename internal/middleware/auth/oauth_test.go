package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/olekukonko/errors"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
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

// createSignedSessionCookie mirrors signSessionCookie exactly so tests stay
// in sync with the production format: <base64(token)>.<expiry_unix>.<base64(hmac)>
func createSignedSessionCookie(token string, expiresAt time.Time, secret []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(token))
	expiry := strconv.FormatInt(expiresAt.Unix(), 10)
	payload := encoded + cookieValueSeparator + expiry
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(payload))
	mac := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return payload + cookieValueSeparator + mac
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
			if c.Name == def.GothSessionCookie && c.Value == validSessionB64 {
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
			Enabled:      expect.Active,
			Provider:     "mock",
			EmailDomains: []string{"example.com"},
			RedirectURL:  "/callback",
		}

		req := httptest.NewRequest("GET", "/callback?code=123&state=xyz", nil)
		req.AddCookie(&http.Cookie{Name: def.GothSessionCookie, Value: validSessionB64})

		rec := httptest.NewRecorder()

		handleGothCallback(rec, req, mockProv, cfg, secret)

		if rec.Code != http.StatusFound {
			t.Errorf("Expected 302 redirect, got %d. Body: %s", rec.Code, rec.Body.String())
		}

		// Cookie format: <base64(token)>.<expiry_unix>.<base64(hmac)>
		cookies := rec.Result().Cookies()
		found := false
		for _, c := range cookies {
			if c.Name != def.SessionCookieName {
				continue
			}
			parts := strings.Split(c.Value, cookieValueSeparator)
			if len(parts) != 3 {
				t.Errorf("Expected 3-part cookie value, got %d parts: %s", len(parts), c.Value)
				break
			}
			// Part 0: base64(token) — must decode to the access token.
			decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil || string(decoded) != "mock_token_123" {
				t.Errorf("Token part mismatch: decoded=%q err=%v", string(decoded), err)
				break
			}
			// Part 1: expiry_unix — must be a future Unix timestamp.
			expiryUnix, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				t.Errorf("Expiry part is not a valid integer: %s", parts[1])
				break
			}
			if expiryUnix <= time.Now().Unix() {
				t.Errorf("Expiry %d is not in the future", expiryUnix)
				break
			}
			// Part 2: HMAC — verifySessionCookie must accept the full cookie.
			if !verifySessionCookie(c.Value, secret) {
				t.Error("verifySessionCookie rejected a freshly issued cookie")
				break
			}
			found = true
			break
		}
		if !found {
			t.Error("Application session cookie not set with valid signed value")
		}
	})

	t.Run("Handle Callback Domain Unknown", func(t *testing.T) {
		cfg := &alaye.OAuth{
			Enabled:      expect.Active,
			Provider:     "mock",
			EmailDomains: []string{"corp.com"},
			RedirectURL:  "/callback",
		}

		req := httptest.NewRequest("GET", "/callback?code=123&state=xyz", nil)
		req.AddCookie(&http.Cookie{Name: def.GothSessionCookie, Value: validSessionB64})

		rec := httptest.NewRecorder()

		handleGothCallback(rec, req, mockProv, cfg, secret)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Expected 403 Forbidden, got %d", rec.Code)
		}
	})

	t.Run("Expired session cookie is rejected", func(t *testing.T) {
		past := time.Now().Add(-1 * time.Second)
		expired := createSignedSessionCookie("some_token", past, secret)
		if verifySessionCookie(expired, secret) {
			t.Error("verifySessionCookie accepted an expired cookie")
		}
	})

	t.Run("Future session cookie is accepted", func(t *testing.T) {
		future := time.Now().Add(1 * time.Hour)
		valid := createSignedSessionCookie("some_token", future, secret)
		if !verifySessionCookie(valid, secret) {
			t.Error("verifySessionCookie rejected a valid future cookie")
		}
	})

	t.Run("Tampered expiry is rejected", func(t *testing.T) {
		future := time.Now().Add(1 * time.Hour)
		cookie := createSignedSessionCookie("some_token", future, secret)

		// Replace the expiry field with a far-future timestamp, keeping the original MAC.
		parts := strings.Split(cookie, cookieValueSeparator)
		if len(parts) != 3 {
			t.Fatalf("Unexpected cookie format: %s", cookie)
		}
		tampered := parts[0] + cookieValueSeparator + "9999999999" + cookieValueSeparator + parts[2]
		if verifySessionCookie(tampered, secret) {
			t.Error("verifySessionCookie accepted a cookie with a tampered expiry")
		}
	})

	t.Run("Old 2-part cookie format is rejected", func(t *testing.T) {
		// Pre-fix cookies must not silently pass verification.
		encoded := base64.RawURLEncoding.EncodeToString([]byte("some_token"))
		h := hmac.New(sha256.New, secret)
		h.Write([]byte(encoded))
		mac := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
		old := encoded + cookieValueSeparator + mac
		if verifySessionCookie(old, secret) {
			t.Error("verifySessionCookie accepted a legacy 2-part cookie")
		}
	})
}
