package headers

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
)

func TestHeaders_RequestMods(t *testing.T) {
	cfg := &alaye.Headers{
		Request: alaye.Header{
			Enabled: alaye.Active, // Added
			Set:     map[string]string{"X-Test": "set-value"},
			Add:     map[string]string{"X-Multi": "add1"},
			Remove:  []string{"User-Agent"},
		},
	}

	handler := Headers(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") != "set-value" {
			t.Error("Set header not applied")
		}

		// Fix: Check if "add1" exists in the slice of values
		found := slices.Contains(r.Header.Values("X-Multi"), "add1")
		if !found {
			t.Errorf("Add header not applied. Got: %v", r.Header["X-Multi"])
		}

		if r.Header.Get("User-Agent") != "" {
			t.Error("Remove header not applied")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "test-agent")
	req.Header.Add("X-Multi", "pre-existing")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestHeaders_ResponseMods(t *testing.T) {
	cfg := &alaye.Headers{
		Response: alaye.Header{
			Enabled: alaye.Active, // Added
			Set:     map[string]string{"X-Resp": "resp-value"},
			Add:     map[string]string{"X-Resp-Multi": "add2"},
			Remove:  []string{"Content-Type"},
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

	// Fix: httptest.ResponseRecorder stores headers as a map.
	// We check if values contain both.
	vals := w.Header().Values("X-Resp-Multi")
	foundPre, foundAdd := false, false
	for _, v := range vals {
		if v == "pre" {
			foundPre = true
		}
		if v == "add2" {
			foundAdd = true
		}
	}

	if !foundPre || !foundAdd {
		t.Errorf("Response add not applied correctly. Got: %v", vals)
	}

	if w.Header().Get("Content-Type") != "" {
		t.Error("Response remove not applied")
	}
}

func TestHeaders_NoOps(t *testing.T) {
	cfg := &alaye.Headers{} // Empty - both Request and Response are disabled by default

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

func TestHeaders_Disabled(t *testing.T) {
	// Test that explicitly disabled headers don't apply
	cfg := &alaye.Headers{
		Request: alaye.Header{
			Enabled: alaye.Inactive, // Explicitly disabled
			Set:     map[string]string{"X-Test": "should-not-appear"},
		},
		Response: alaye.Header{
			Enabled: alaye.Inactive, // Explicitly disabled
			Set:     map[string]string{"X-Resp": "should-not-appear"},
		},
	}

	handler := Headers(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test") != "" {
			t.Error("Disabled request header was applied")
		}
		w.Header().Set("X-Check", "value")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	if w.Header().Get("X-Resp") != "" {
		t.Error("Disabled response header was applied")
	}
}
