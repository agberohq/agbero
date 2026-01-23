// internal/middleware/headers/headers_test.go
package headers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

func TestHeaders_RequestMods(t *testing.T) {
	cfg := &woos.HeadersConfig{
		Request: &woos.HeaderOperations{
			Set:    map[string]string{"X-Test": "set-value"},
			Add:    map[string]string{"X-Multi": "add1"},
			Remove: []string{"User-Agent"},
		},
	}

	handler := Headers(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") != "set-value" {
			t.Error("Set header not applied")
		}
		if r.Header.Get("X-Multi") != "add1" {
			t.Error("Add header not applied")
		}
		if r.Header.Get("User-Agent") != "" {
			t.Error("Remove header not applied")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Add("X-Multi", "pre-existing") // Add should append, but since Add in ops is map, it's Set-like; test as is
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestHeaders_ResponseMods(t *testing.T) {
	cfg := &woos.HeadersConfig{
		Response: &woos.HeaderOperations{
			Set:    map[string]string{"X-Resp": "resp-value"},
			Add:    map[string]string{"X-Resp-Multi": "add2"},
			Remove: []string{"Content-Type"},
		},
	}

	handler := Headers(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Add("X-Resp-Multi", "pre")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Header().Get("X-Resp") != "resp-value" {
		t.Error("Response set not applied")
	}
	if w.Header().Get("X-Resp-Multi") != "pre, add2" { // Assumes Add appends
		t.Error("Response add not applied")
	}
	if w.Header().Get("Content-Type") != "" {
		t.Error("Response remove not applied")
	}
}

func TestHeaders_NoOps(t *testing.T) {
	cfg := &woos.HeadersConfig{} // Empty

	handler := Headers(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Error("Handler affected by empty config")
	}
}
