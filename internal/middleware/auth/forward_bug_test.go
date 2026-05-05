package auth

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/resource"
)

// plainDialer is injected in tests that need to reach httptest servers on
// 127.0.0.1 without setting AllowPrivate = true on the config.
var plainDialer = (&net.Dialer{Timeout: time.Second}).DialContext

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

func TestIsPrivateIPForward(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
		desc string
	}{
		// Private / blocked
		{"127.0.0.1", true, "IPv4 loopback"},
		{"::1", true, "IPv6 loopback"},
		{"169.254.169.254", true, "AWS/GCP metadata endpoint"},
		{"169.254.0.1", true, "link-local"},
		{"10.0.0.1", true, "RFC-1918 10/8"},
		{"172.16.0.1", true, "RFC-1918 172.16/12"},
		{"192.168.1.1", true, "RFC-1918 192.168/16"},
		{"100.64.0.1", true, "carrier-grade NAT"},
		{"fc00::1", true, "IPv6 ULA"},
		{"fe80::1", true, "IPv6 link-local"},
		{"0.0.0.0", true, "unspecified"},

		// Public / allowed
		{"8.8.8.8", false, "Google DNS"},
		{"1.1.1.1", false, "Cloudflare DNS"},
		{"203.0.113.1", false, "TEST-NET-3 (documentation, public)"},
		{"2001:db8::1", false, "IPv6 documentation range (public)"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("ParseIP(%q) returned nil", tt.ip)
			}
			got := alaye.IsPrivateIP(ip)
			if got != tt.want {
				t.Errorf("isPrivateIPForward(%s) = %v, want %v (%s)", tt.ip, got, tt.want, tt.desc)
			}
		})
	}
}

// ssrfSafeDialContext unit tests

func TestSSRFSafeDialContext_BlocksPrivate(t *testing.T) {
	dialer := &net.Dialer{Timeout: time.Second}
	dialFn := ssrfSafeDialContext(dialer)

	privateAddrs := []string{
		"127.0.0.1:80",
		"169.254.169.254:80",
		"10.0.0.1:80",
		"172.16.0.1:80",
		"192.168.1.1:8080",
		"[::1]:80",
		"[fe80::1]:80",
	}

	for _, addr := range privateAddrs {
		conn, err := dialFn(context.Background(), "tcp", addr)
		if err == nil {
			conn.Close()
			t.Errorf("ssrfSafeDialContext allowed connection to private address %q — SSRF not blocked", addr)
			continue
		}
		if !strings.Contains(err.Error(), "SSRF protection") {
			t.Errorf("ssrfSafeDialContext(%q): error %q does not mention SSRF protection", addr, err)
		}
	}
}

func TestSSRFSafeDialContext_AllowsPublic(t *testing.T) {
	dialer := &net.Dialer{Timeout: 100 * time.Millisecond}
	dialFn := ssrfSafeDialContext(dialer)

	// The connection will time out in CI; we only care the error is not an SSRF block.
	_, err := dialFn(context.Background(), "tcp", "8.8.8.8:80")
	if err != nil && strings.Contains(err.Error(), "SSRF protection") {
		t.Errorf("ssrfSafeDialContext blocked public IP 8.8.8.8 — overly aggressive SSRF filter")
	}
}

// Integration: Forward middleware SSRF protection

// TestForward_SSRFDialer_BlocksPrivateAtDial verifies the runtime DialContext
// guard catches private IPs even when AllowPrivate is false.
func TestForward_SSRFDialer_BlocksPrivateAtDial(t *testing.T) {
	cfg := &alaye.ForwardAuth{
		Enabled: expect.Active,
		URL:     "http://169.254.169.254/latest/meta-data/",
		Timeout: expect.Duration(int64(time.Second)),
	}
	handler := Forward(resource.New(), cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("SSRF: forward_auth reached the protected handler — metadata endpoint was not blocked")
	}
}

// TestForward_SSRFDialer_AllowsPublic verifies a real (non-private) auth server
// is reachable. We use newForwardAuthWithDialer with a plain dialer so the
// httptest server's 127.0.0.1 address is not blocked by ssrfSafeDialContext —
// in production the auth server would have a real public IP.
func TestForward_SSRFDialer_AllowsPublic(t *testing.T) {
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer authServer.Close()

	cfg := &alaye.ForwardAuth{
		Enabled: expect.Active,
		URL:     authServer.URL,
		Timeout: expect.Duration(int64(time.Second)),
	}

	reached := false
	// plainDialer bypasses the SSRF check so the httptest server is reachable.
	handler := newForwardAuthWithDialer(resource.New(), cfg, plainDialer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !reached {
		t.Errorf("Forward middleware blocked a legitimate auth server (status=%d)", w.Code)
	}
}

// TestForward_SSRFDialer_PresentOnBothClientPaths confirms the safe dialer is
// wired into both the TLS and non-TLS paths.
func TestForward_SSRFDialer_PresentOnBothClientPaths(t *testing.T) {
	for _, tlsEnabled := range []bool{false, true} {
		name := "non-TLS"
		if tlsEnabled {
			name = "TLS"
		}
		t.Run(name, func(t *testing.T) {
			enabled := expect.Inactive
			if tlsEnabled {
				enabled = expect.Active
			}
			cfg := &alaye.ForwardAuth{
				Enabled: expect.Active,
				URL:     "http://10.0.0.1/auth",
				Timeout: expect.Duration(int64(time.Second)),
				TLS:     alaye.ForwardTLS{Enabled: enabled},
			}
			handler := Forward(resource.New(), cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code == http.StatusOK {
				t.Errorf("[%s] SSRF: request reached handler via private IP 10.0.0.1", name)
			}
		})
	}
}
