package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/hub/resource"
)

var res = resource.New()

func TestForward_Disabled(t *testing.T) {
	cfg := &alaye.ForwardAuth{Enabled: expect.Inactive}
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("next-handler"))
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 when disabled, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "next-handler") {
		t.Error("Next handler should be called when disabled")
	}
}

func TestForward_EmptyURL(t *testing.T) {
	cfg := &alaye.ForwardAuth{Enabled: expect.Active, URL: ""}
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 when URL empty, got %d", w.Code)
	}
}

func TestForward_Success_AllowsRequest(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("Authorization header not forwarded")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_success_allows",
		URL:          authServer.URL,
		AllowPrivate: true, // test server binds to loopback
		Request: alaye.ForwardAuthRequest{
			Enabled: expect.Active,
			Headers: []string{"Authorization"},
		},
	}

	called := false
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("protected-resource"))
	}))

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if !called {
		t.Error("Next handler should be called on auth success")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	if w.Body.String() != "protected-resource" {
		t.Errorf("Expected body 'protected-resource', got %s", w.Body.String())
	}
}

func TestForward_Forbidden_BlocksRequest(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"insufficient_scope"}`))
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_forbidden_blocks",
		URL:          authServer.URL,
		AllowPrivate: true,
	}

	nextCalled := false
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/admin", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if nextCalled {
		t.Error("Next handler should NOT be called on auth failure")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "insufficient_scope") {
		t.Errorf("Expected auth error body, got %s", w.Body.String())
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Error("Content-Type header should be preserved from auth service")
	}
}

func TestForward_Unauthorized(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="api", error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_token"}`))
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_unauthorized",
		URL:          authServer.URL,
		AllowPrivate: true,
	}
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/api/resource", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("WWW-Authenticate header should be preserved")
	}
}

func TestForward_DefaultHeaders(t *testing.T) {
	receivedHeaders := make(http.Header)
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_default_headers",
		URL:          authServer.URL,
		AllowPrivate: true,
	}
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer token123")
	req.Header.Set("Cookie", "session=abc")
	req.Header.Set("X-Custom", "should-not-forward")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if receivedHeaders.Get("Authorization") != "Bearer token123" {
		t.Error("Authorization should be forwarded by default")
	}
	if receivedHeaders.Get("Cookie") != "session=abc" {
		t.Error("Cookie should be forwarded by default")
	}
	if receivedHeaders.Get("X-Custom") != "" {
		t.Error("Custom headers should NOT be forwarded by default")
	}
}

func TestForward_CustomHeaders(t *testing.T) {
	receivedHeaders := make(http.Header)
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_custom_headers",
		URL:          authServer.URL,
		AllowPrivate: true,
		Request: alaye.ForwardAuthRequest{
			Enabled: expect.Active,
			Headers: []string{"X-API-Key", "X-Tenant-ID"},
		},
	}
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-API-Key", "secret-key")
	req.Header.Set("X-Tenant-ID", "tenant-123")
	req.Header.Set("Authorization", "should-not-forward")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if receivedHeaders.Get("X-API-Key") != "secret-key" {
		t.Error("X-API-Key should be forwarded")
	}
	if receivedHeaders.Get("X-Tenant-ID") != "tenant-123" {
		t.Error("X-Tenant-ID should be forwarded")
	}
	if receivedHeaders.Get("Authorization") != "" {
		t.Error("Authorization should NOT be forwarded when not in list")
	}
}

func TestForward_MetadataHeaders(t *testing.T) {
	receivedHeaders := make(http.Header)
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_metadata_headers",
		URL:          authServer.URL,
		AllowPrivate: true,
		Request: alaye.ForwardAuthRequest{
			Enabled:       expect.Active,
			ForwardMethod: true,
			ForwardURI:    true,
			ForwardIP:     true,
		},
	}
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest("POST", "/api/v1/users?page=2", nil)
	req.RemoteAddr = "192.168.1.100:12345"

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if receivedHeaders.Get(woos.HeaderXOriginalMethod) != "POST" {
		t.Errorf("Expected method POST, got %s", receivedHeaders.Get(woos.HeaderXOriginalMethod))
	}
	if receivedHeaders.Get(woos.HeaderXOriginalURI) != "/api/v1/users?page=2" {
		t.Errorf("Expected URI /api/v1/users?page=2, got %s", receivedHeaders.Get(woos.HeaderXOriginalURI))
	}
	if receivedHeaders.Get(woos.HeaderXForwardedFor) != "192.168.1.100" {
		t.Errorf("Expected IP 192.168.1.100, got %s", receivedHeaders.Get(woos.HeaderXForwardedFor))
	}
}

func TestForward_CopyHeadersToBackend(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-User-ID", "user-123")
		w.Header().Set("X-User-Email", "alice@example.com")
		w.Header().Set("X-User-Scopes", "read,write,admin")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	var receivedUserID, receivedEmail, receivedScopes string
	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_copy_headers",
		URL:          authServer.URL,
		AllowPrivate: true,
		Response: alaye.ForwardAuthResponse{
			Enabled:     expect.Active,
			CopyHeaders: []string{"X-User-ID", "X-User-Email", "X-User-Scopes"},
		},
	}
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUserID = r.Header.Get("X-User-ID")
		receivedEmail = r.Header.Get("X-User-Email")
		receivedScopes = r.Header.Get("X-User-Scopes")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if receivedUserID != "user-123" {
		t.Errorf("Expected X-User-ID user-123, got %s", receivedUserID)
	}
	if receivedEmail != "alice@example.com" {
		t.Errorf("Expected X-User-Email alice@example.com, got %s", receivedEmail)
	}
	if receivedScopes != "read,write,admin" {
		t.Errorf("Expected X-User-Scopes read,write,admin, got %s", receivedScopes)
	}
}

func TestForward_BodyMode_None(t *testing.T) {
	bodyReceived := false
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			if len(body) > 0 {
				bodyReceived = true
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_body_none",
		URL:          authServer.URL,
		AllowPrivate: true,
		Request: alaye.ForwardAuthRequest{
			Enabled:  expect.Active,
			BodyMode: "none",
		},
	}
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"data":"sensitive"}` {
			t.Errorf("Backend should receive original body, got %s", string(body))
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/api/data", strings.NewReader(`{"data":"sensitive"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if bodyReceived {
		t.Error("Internal service should NOT receive body in 'none' mode")
	}
}

func TestForward_BodyMode_Metadata(t *testing.T) {
	receivedHeaders := make(http.Header)
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			if len(body) > 0 {
				t.Error("Internal service should not receive body in 'metadata' mode")
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_body_metadata",
		URL:          authServer.URL,
		AllowPrivate: true,
		Request: alaye.ForwardAuthRequest{
			Enabled:  expect.Active,
			BodyMode: "metadata",
			Method:   http.MethodPost,
		},
	}
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != "large-file-content" {
			t.Errorf("Backend should receive original body, got %q", string(body))
		}
		w.WriteHeader(http.StatusOK)
	}))

	bodyContent := "large-file-content"
	req := httptest.NewRequest("POST", "/api/upload", strings.NewReader(bodyContent))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(bodyContent))
	req.Header.Set("Content-Length", strconv.Itoa(len(bodyContent)))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if receivedHeaders.Get("Content-Type") != "application/octet-stream" {
		t.Errorf("Content-Type should be forwarded in metadata mode, got %q", receivedHeaders.Get("Content-Type"))
	}
}

func TestForward_BodyMode_Limited(t *testing.T) {
	authBody := ""
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			body, _ := io.ReadAll(r.Body)
			authBody = string(body)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_body_limited",
		URL:          authServer.URL,
		AllowPrivate: true,
		Request: alaye.ForwardAuthRequest{
			Enabled:  expect.Active,
			BodyMode: "limited",
			MaxBody:  100,
		},
	}

	backendBody := ""
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		backendBody = string(body)
		w.WriteHeader(http.StatusOK)
	}))

	// Small body — sent to both auth and backend
	smallBody := `{"action":"create","resource":"user"}`
	req := httptest.NewRequest("POST", "/api/resource", strings.NewReader(smallBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if authBody != smallBody {
		t.Errorf("Internal service should receive body, got %s", authBody)
	}
	if backendBody != smallBody {
		t.Errorf("Backend should receive full body, got %s", backendBody)
	}

	// Large body — truncated for auth, full for backend
	largeBody := strings.Repeat("x", 1000)
	authBody = ""
	backendBody = ""
	req2 := httptest.NewRequest("POST", "/api/resource", strings.NewReader(largeBody))
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if len(authBody) != 100 {
		t.Errorf("Internal service should receive only 100 bytes, got %d", len(authBody))
	}
	if backendBody != largeBody {
		t.Errorf("Backend should receive full 1000 bytes, got %d", len(backendBody))
	}
}

func TestForward_OnFailure_Allow(t *testing.T) {
	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_failure_allow",
		URL:          "http://127.0.0.1:1",
		OnFailure:    "allow",
		Timeout:      alaye.Duration(100 * time.Millisecond),
		AllowPrivate: true,
	}

	called := false
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("fail-open"))
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("Next handler should be called when on_failure=allow")
	}
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 on failure allow, got %d", w.Code)
	}
}

func TestForward_OnFailure_Deny(t *testing.T) {
	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_failure_deny",
		URL:          "http://127.0.0.1:1",
		OnFailure:    "deny",
		Timeout:      alaye.Duration(100 * time.Millisecond),
		AllowPrivate: true,
	}

	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Next handler should NOT be called when on_failure=deny")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403 on failure deny, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "auth service unavailable") {
		t.Errorf("Expected error message, got %s", w.Body.String())
	}
}

func TestForward_Timeout(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_timeout",
		URL:          authServer.URL,
		Timeout:      alaye.Duration(50 * time.Millisecond),
		OnFailure:    "deny",
		AllowPrivate: true,
	}
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Should not reach next handler on timeout")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403 on timeout, got %d", w.Code)
	}
}

func TestForward_TLS_InsecureSkipVerify(t *testing.T) {
	authServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_tls_skip_verify",
		URL:          authServer.URL,
		AllowPrivate: true,
		TLS: alaye.ForwardTLS{
			Enabled:            expect.Active,
			InsecureSkipVerify: true,
		},
	}
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 with insecure skip verify, got %d", w.Code)
	}
}

func TestForward_EmptyAuthorization(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_empty_auth",
		URL:          authServer.URL,
		AllowPrivate: true,
	}
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Should not reach next handler without auth")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 without auth, got %d", w.Code)
	}
}

func TestForward_AuthService5xx(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"auth_service_overloaded"}`))
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_5xx",
		URL:          authServer.URL,
		OnFailure:    "deny",
		AllowPrivate: true,
	}
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Should not reach next handler on 503")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 from auth service, got %d", w.Code)
	}
}

func TestForward_ConcurrentRequests(t *testing.T) {
	var authCalls int64
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&authCalls, 1)
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_concurrent",
		URL:          authServer.URL,
		AllowPrivate: true,
		Request: alaye.ForwardAuthRequest{
			Enabled:  expect.Active,
			CacheKey: []string{"Authorization"},
		},
		Response: alaye.ForwardAuthResponse{
			Enabled:  expect.Active,
			CacheTTL: alaye.Duration(1 * time.Minute),
		},
	}
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	var wg sync.WaitGroup
	successCount := int64(0)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("Authorization", "Bearer concurrent-token")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code == http.StatusOK {
				atomic.AddInt64(&successCount, 1)
			}
		}()
	}
	wg.Wait()

	if successCount != 10 {
		t.Errorf("Expected 10 successes, got %d", successCount)
	}
}

func TestForward_LargeResponseHeaders(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		largeToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." + strings.Repeat("x", 2000) + ".signature"
		w.Header().Set("X-User-Token", largeToken)
		w.Header().Set("X-User-ID", "user-123")
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_large_headers",
		URL:          authServer.URL,
		AllowPrivate: true,
		Response: alaye.ForwardAuthResponse{
			Enabled:     expect.Active,
			CopyHeaders: []string{"X-User-Token", "X-User-ID"},
		},
	}

	var receivedToken string
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedToken = r.Header.Get("X-User-Token")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if len(receivedToken) < 2000 {
		t.Error("Large token should be copied to backend")
	}
}

func TestForward_SpecialCharactersInURI(t *testing.T) {
	receivedURI := ""
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedURI = r.Header.Get(woos.HeaderXOriginalURI)
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_special_uri",
		URL:          authServer.URL,
		AllowPrivate: true,
		Request: alaye.ForwardAuthRequest{
			Enabled:    expect.Active,
			ForwardURI: true,
		},
	}
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/search?q=hello+world&filter=name%3Dtest", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !strings.Contains(receivedURI, "hello+world") {
		t.Errorf("URI should contain query params, got %s", receivedURI)
	}
}

// TestForward_SSRF_Rejected verifies that a private URL without allow_private = true
// is rejected at Validate() time, not at request time.
func TestForward_SSRF_Rejected(t *testing.T) {
	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_ssrf",
		URL:          "http://127.0.0.1:9999/",
		OnFailure:    "deny",
		Timeout:      alaye.Duration(woos.DefaultForwardAuthTimeout),
		AllowPrivate: false,
	}
	// Config-time check is where the SSRF guard fires.
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() must reject a loopback URL when allow_private = false")
	}
}

// TestForward_SSRF_AllowPrivate verifies that allow_private = true passes Validate().
func TestForward_SSRF_AllowPrivate(t *testing.T) {
	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_ssrf_allow",
		URL:          "http://127.0.0.1:9999/",
		OnFailure:    "deny",
		Timeout:      alaye.Duration(woos.DefaultForwardAuthTimeout),
		AllowPrivate: true,
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() must accept loopback when allow_private = true, got: %v", err)
	}
}
