package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
)

func TestForward_SpoofAdmin(t *testing.T) {
	// Auth server authenticates as a normal user, returns 200 but NO X-User-Role header
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Successfully authenticated as a normal user
		// Intentionally NOT setting X-User-Role (user has default role)
		w.Header().Set("X-User-ID", "user-456")
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_spoof_admin",
		URL:          authServer.URL,
		AllowPrivate: true,
		Response: alaye.ForwardAuthResponse{
			Enabled:     expect.Active,
			CopyHeaders: []string{"X-User-ID", "X-User-Role"},
		},
	}

	var receivedRole, receivedID string
	var allRoles []string
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedID = r.Header.Get("X-User-ID")
		receivedRole = r.Header.Get("X-User-Role")
		allRoles = r.Header["X-User-Role"]
		w.WriteHeader(http.StatusOK)
	}))

	// Attacker sends request with spoofed X-User-Role header
	req := httptest.NewRequest("GET", "/admin/dashboard", nil)
	req.Header.Set("X-User-Role", "admin") // SPOOFED HEADER!
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Bug verification
	if receivedID != "user-456" {
		t.Errorf("Expected X-User-ID user-456, got %s", receivedID)
	}

	// THIS IS THE BUG: Agbero never stripped the original headers,
	// so the attacker's spoofed header persists
	if receivedRole == "admin" {
		t.Error("BUG CONFIRMED: Attacker successfully spoofed X-User-Role as 'admin'")
		t.Log("Auth server didn't set X-User-Role, but attacker's header was passed through")
		t.Log("All X-User-Role values:", allRoles)
	}

	// What SHOULD happen: receivedRole should be empty string
	// since the auth server didn't set it
	if receivedRole == "" {
		t.Log("Expected behavior: role is empty when auth server doesn't set it")
	}
}

func TestForward_SpoofAdmin_SecondBug_MultipleHeaders(t *testing.T) {
	// Auth server sends multiple X-User-Role values
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("X-User-Role", "user")
		w.Header().Add("X-User-Role", "editor")
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_multiple_header_values",
		URL:          authServer.URL,
		AllowPrivate: true,
		Response: alaye.ForwardAuthResponse{
			Enabled:     expect.Active,
			CopyHeaders: []string{"X-User-Role"},
		},
	}

	var receivedRole string
	var allRoles []string
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Header.Get() only returns the first value - SECONDARY BUG
		receivedRole = r.Header.Get("X-User-Role")
		allRoles = r.Header["X-User-Role"]
		t.Log("All X-User-Role values in request:", allRoles)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if receivedRole == "user" {
		t.Log("SECOND BUG CONFIRMED: Only first header value 'user' was copied, 'editor' was lost")
	}

	// Check if we actually lost the second value
	if len(allRoles) < 2 {
		t.Error("BUG: Multiple header values from auth server were not all preserved")
		t.Logf("Expected both 'user' and 'editor', got %d values: %v", len(allRoles), allRoles)
	}
}

func TestForward_SpoofAdmin_ProperFix(t *testing.T) {
	// This test demonstrates the FIX: should strip headers before forwarding to backend
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-User-Role", "user") // Auth server sets actual role
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled:      expect.Active,
		Name:         "test_proper_fix",
		URL:          authServer.URL,
		AllowPrivate: true,
		Response: alaye.ForwardAuthResponse{
			Enabled:     expect.Active,
			CopyHeaders: []string{"X-User-Role", "X-User-ID"},
		},
	}

	var receivedRole string
	handler := Forward(res, cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRole = r.Header.Get("X-User-Role")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("X-User-Role", "admin") // Attacker tries to spoof
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// The fix should ensure the attacker's header is stripped,
	// and only the auth server's value appears
	if receivedRole == "user" {
		t.Log("FIX WORKS: Attacker's 'admin' was stripped, auth server's 'user' used")
	} else if receivedRole == "admin" {
		t.Error("FIX FAILED: Attacker can still spoof admin role")
	} else {
		t.Log("Received role:", receivedRole)
	}
}
