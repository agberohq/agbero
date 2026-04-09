package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/middleware/firewall"
	"github.com/go-chi/chi/v5"
)

func setupTestFirewall(t *testing.T) (*Shared, func()) {
	t.Helper()
	tmpDir := t.TempDir()

	cfg := firewall.Config{
		Firewall: &alaye.Firewall{
			Status: expect.Active,
			Mode:   "active",
			Rules:  []alaye.Rule{},
		},
		DataDir:        expect.NewFolder(tmpDir),
		Logger:         testLogger,
		TrustedProxies: []string{},
	}

	engine, err := firewall.New(cfg)
	if err != nil {
		t.Fatalf("Failed to create firewall: %v", err)
	}

	shared := &Shared{
		Logger: testLogger,
	}

	// Initialize the state with the firewall engine
	shared.UpdateState(&ActiveState{
		Firewall: engine,
	})

	cleanup := func() {
		engine.Close()
	}

	return shared, cleanup
}

func TestFirewallHandler_List_Enabled(t *testing.T) {
	shared, cleanup := setupTestFirewall(t)
	defer cleanup()

	r := chi.NewRouter()
	FirewallHandler(shared, r)

	req := httptest.NewRequest(http.MethodGet, "/firewall", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if enabled, ok := resp["enabled"].(bool); !ok || !enabled {
		t.Error("Expected enabled to be true")
	}
}

func TestFirewallHandler_List_Disabled(t *testing.T) {
	shared := &Shared{
		Logger: testLogger,
	}

	// Set state with nil firewall
	shared.UpdateState(&ActiveState{
		Firewall: nil,
	})

	r := chi.NewRouter()
	FirewallHandler(shared, r)

	req := httptest.NewRequest(http.MethodGet, "/firewall", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if enabled, ok := resp["enabled"].(bool); !ok || enabled {
		t.Error("Expected enabled to be false")
	}
}

func TestFirewallHandler_Block(t *testing.T) {
	shared, cleanup := setupTestFirewall(t)
	defer cleanup()

	r := chi.NewRouter()
	FirewallHandler(shared, r)

	reqBody := map[string]interface{}{
		"ip":           "192.168.1.100",
		"reason":       "test block",
		"host":         "example.com",
		"path":         "/api/test",
		"duration_sec": 3600,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/firewall", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	if w.Body.String() != "Blocked" {
		t.Errorf("Expected 'Blocked', got %s", w.Body.String())
	}

	engine := shared.State().Firewall
	rules, err := engine.List()
	if err != nil {
		t.Fatalf("Failed to list rules: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(rules))
	}
	if rules[0].IP != "192.168.1.100" {
		t.Errorf("Expected IP 192.168.1.100, got %s", rules[0].IP)
	}
	if rules[0].Reason != "test block (host=example.com, path=/api/test)" {
		t.Errorf("Expected reason with context, got %s", rules[0].Reason)
	}
}

func TestFirewallHandler_Block_CIDR(t *testing.T) {
	shared, cleanup := setupTestFirewall(t)
	defer cleanup()

	r := chi.NewRouter()
	FirewallHandler(shared, r)

	reqBody := map[string]interface{}{
		"ip":           "192.168.1.0/24",
		"reason":       "block subnet",
		"duration_sec": 7200,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/firewall", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	engine := shared.State().Firewall
	rules, err := engine.List()
	if err != nil {
		t.Fatalf("Failed to list rules: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(rules))
	}
	if rules[0].IP != "192.168.1.0/24" {
		t.Errorf("Expected IP 192.168.1.0/24, got %s", rules[0].IP)
	}
}

func TestFirewallHandler_Block_InvalidIP(t *testing.T) {
	shared, cleanup := setupTestFirewall(t)
	defer cleanup()

	r := chi.NewRouter()
	FirewallHandler(shared, r)

	reqBody := map[string]interface{}{
		"ip":           "invalid-ip",
		"reason":       "test",
		"duration_sec": 3600,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/firewall", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestFirewallHandler_Block_NoIP(t *testing.T) {
	shared, cleanup := setupTestFirewall(t)
	defer cleanup()

	r := chi.NewRouter()
	FirewallHandler(shared, r)

	reqBody := map[string]interface{}{
		"reason":       "test",
		"duration_sec": 3600,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/firewall", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestFirewallHandler_Block_Disabled(t *testing.T) {
	shared := &Shared{
		Logger: testLogger,
	}

	// Set state with nil firewall
	shared.UpdateState(&ActiveState{
		Firewall: nil,
	})

	r := chi.NewRouter()
	FirewallHandler(shared, r)

	reqBody := map[string]interface{}{
		"ip":           "192.168.1.100",
		"reason":       "test",
		"duration_sec": 3600,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/firewall", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("Expected 501, got %d", w.Code)
	}
}

func TestFirewallHandler_Unblock(t *testing.T) {
	shared, cleanup := setupTestFirewall(t)
	defer cleanup()

	r := chi.NewRouter()
	FirewallHandler(shared, r)

	// First block an IP
	blockBody := map[string]interface{}{
		"ip":           "192.168.1.100",
		"reason":       "test",
		"duration_sec": 3600,
	}
	blockJSON, _ := json.Marshal(blockBody)
	blockReq := httptest.NewRequest(http.MethodPost, "/firewall", bytes.NewReader(blockJSON))
	blockW := httptest.NewRecorder()
	r.ServeHTTP(blockW, blockReq)

	if blockW.Code != http.StatusOK {
		t.Fatalf("Failed to block IP: %d", blockW.Code)
	}

	engine := shared.State().Firewall
	// Verify it exists
	rules, err := engine.List()
	if err != nil {
		t.Fatalf("Failed to list rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("Expected 1 rule before unblock, got %d", len(rules))
	}

	// Unblock
	unblockReq := httptest.NewRequest(http.MethodDelete, "/firewall?ip=192.168.1.100", nil)
	unblockW := httptest.NewRecorder()
	r.ServeHTTP(unblockW, unblockReq)

	if unblockW.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", unblockW.Code)
	}

	if unblockW.Body.String() != "Unblocked" {
		t.Errorf("Expected 'Unblocked', got %s", unblockW.Body.String())
	}

	// Verify it's gone
	rules, err = engine.List()
	if err != nil {
		t.Fatalf("Failed to list rules: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("Expected 0 rules after unblock, got %d", len(rules))
	}
}

func TestFirewallHandler_Unblock_NoIP(t *testing.T) {
	shared, cleanup := setupTestFirewall(t)
	defer cleanup()

	r := chi.NewRouter()
	FirewallHandler(shared, r)

	unblockReq := httptest.NewRequest(http.MethodDelete, "/firewall", nil)
	unblockW := httptest.NewRecorder()
	r.ServeHTTP(unblockW, unblockReq)

	if unblockW.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", unblockW.Code)
	}
}

func TestFirewallHandler_Unblock_InvalidIP(t *testing.T) {
	shared, cleanup := setupTestFirewall(t)
	defer cleanup()

	r := chi.NewRouter()
	FirewallHandler(shared, r)

	unblockReq := httptest.NewRequest(http.MethodDelete, "/firewall?ip=invalid-ip", nil)
	unblockW := httptest.NewRecorder()
	r.ServeHTTP(unblockW, unblockReq)

	if unblockW.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", unblockW.Code)
	}
}

func TestFirewallHandler_Unblock_Disabled(t *testing.T) {
	shared := &Shared{
		Logger: testLogger,
	}

	// Set state with nil firewall
	shared.UpdateState(&ActiveState{
		Firewall: nil,
	})

	r := chi.NewRouter()
	FirewallHandler(shared, r)

	unblockReq := httptest.NewRequest(http.MethodDelete, "/firewall?ip=192.168.1.100", nil)
	unblockW := httptest.NewRecorder()
	r.ServeHTTP(unblockW, unblockReq)

	if unblockW.Code != http.StatusNotImplemented {
		t.Errorf("Expected 501, got %d", unblockW.Code)
	}
}

func TestIsValidIPOrCIDR(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"192.168.1.1", true},
		{"192.168.1.0/24", true},
		{"2001:db8::1", true},
		{"2001:db8::/32", true},
		{"invalid", false},
		{"", false},
		{"256.256.256.256", false},
		{"192.168.1.0/33", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := isValidIPOrCIDR(tt.input)
			if result != tt.expected {
				t.Errorf("isValidIPOrCIDR(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBuildBlockReason(t *testing.T) {
	tests := []struct {
		reason   string
		host     string
		path     string
		expected string
	}{
		{"test", "", "", "test"},
		{"test", "example.com", "", "test (host=example.com)"},
		{"test", "", "/api", "test (path=/api)"},
		{"test", "example.com", "/api", "test (host=example.com, path=/api)"},
		{"", "example.com", "/api", " (host=example.com, path=/api)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := buildBlockReason(tt.reason, tt.host, tt.path)
			if result != tt.expected {
				t.Errorf("buildBlockReason(%q, %q, %q) = %q, expected %q",
					tt.reason, tt.host, tt.path, result, tt.expected)
			}
		})
	}
}
