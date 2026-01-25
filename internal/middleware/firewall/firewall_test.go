package firewall

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
)

// newTestLogger creates a silent logger for tests.
func newTestLogger() *ll.Logger {
	return ll.New("test")
}

// createTempDir helper to create and clean up temporary directories.
func createTempDir(t *testing.T) string {
	dir, err := os.MkdirTemp("", "agbero-firewall-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// mockHandler is a simple handler that returns 200 OK.
var mockHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestFirewall_LocalBlock(t *testing.T) {
	dataDir := createTempDir(t)
	cfg := &alaye.Firewall{Enabled: true}

	f, err := New(cfg, woos.NewFolder(dataDir), newTestLogger())
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer f.Close()

	// Block specific IP
	if err := f.Block("192.168.1.100", "test", 0); err != nil {
		t.Fatalf("Block failed: %v", err)
	}

	// Block CIDR
	if err := f.Block("10.0.0.0/24", "test_cidr", 0); err != nil {
		t.Fatalf("Block CIDR failed: %v", err)
	}

	tests := []struct {
		ip      string
		allowed bool
	}{
		{"192.168.1.100", false}, // Explicitly blocked
		{"192.168.1.101", true},  // Allowed
		{"10.0.0.5", false},      // Blocked by CIDR
		{"10.0.1.5", true},       // Outside CIDR
		{"::1", true},            // IPv6 Allowed
	}

	handler := f.Handler(mockHandler)

	for _, tt := range tests {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = tt.ip + ":12345"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if tt.allowed && w.Code != http.StatusOK {
			t.Errorf("IP %s should be allowed, got status %d", tt.ip, w.Code)
		}
		if !tt.allowed && w.Code != http.StatusForbidden {
			t.Errorf("IP %s should be blocked, got status %d", tt.ip, w.Code)
		}
	}
}

func TestFirewall_IPv4MappedIPv6(t *testing.T) {
	dataDir := createTempDir(t)
	cfg := &alaye.Firewall{Enabled: true}

	f, err := New(cfg, woos.NewFolder(dataDir), newTestLogger())
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer f.Close()

	// Block plain IPv4
	f.Block("1.2.3.4", "test", 0)

	// Test with IPv4-mapped IPv6 address (::ffff:1.2.3.4)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "[::ffff:1.2.3.4]:12345"
	w := httptest.NewRecorder()

	f.Handler(mockHandler).ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("IPv4-mapped IPv6 address was not blocked correctly")
	}
}

func TestFirewall_Expiration(t *testing.T) {
	dataDir := createTempDir(t)
	cfg := &alaye.Firewall{Enabled: true}

	f, err := New(cfg, woos.NewFolder(dataDir), newTestLogger())
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer f.Close()

	// Block for extremely short duration
	f.Block("1.1.1.1", "temp", 10*time.Millisecond)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.1.1.1:1234"

	// Immediately check - should be blocked
	w1 := httptest.NewRecorder()
	f.Handler(mockHandler).ServeHTTP(w1, req)
	if w1.Code != http.StatusForbidden {
		t.Error("IP should be blocked initially")
	}

	// Wait for expiration
	time.Sleep(50 * time.Millisecond)

	// NOTE: The current implementation loads expiry from BoltDB at startup.
	// It relies on reloading to clear expired entries from memory unless
	// we implement a memory reaper or check expiry on access.
	//
	// However, Store.LoadAll() DOES filter expired keys.
	// So let's simulate a restart to verify persistence logic handles expiry correctly.

	f.Close()

	f2, err := New(cfg, woos.NewFolder(dataDir), newTestLogger())
	if err != nil {
		t.Fatalf("Restart failed: %v", err)
	}
	defer f2.Close()

	w2 := httptest.NewRecorder()
	f2.Handler(mockHandler).ServeHTTP(w2, req)
	if w2.Code != http.StatusOK {
		t.Error("IP should be allowed after expiration and restart")
	}
}

func TestFirewall_ImportFile(t *testing.T) {
	dataDir := createTempDir(t)
	blockFile := filepath.Join(dataDir, "blocked.txt")
	content := `
# Comment
1.2.3.4
10.0.0.0/24
bad_ip_ignored
`
	if err := os.WriteFile(blockFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &alaye.Firewall{
		Enabled:   true,
		BlockList: blockFile,
	}

	f, err := New(cfg, woos.NewFolder(dataDir), newTestLogger())
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer f.Close()

	// 1.2.3.4 should be blocked
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	w := httptest.NewRecorder()
	f.Handler(mockHandler).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Error("Imported single IP not blocked")
	}

	// 10.0.0.5 should be blocked (CIDR)
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "10.0.0.5:5555"
	w2 := httptest.NewRecorder()
	f.Handler(mockHandler).ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Error("Imported CIDR not blocked")
	}
}

func TestFirewall_RemoteCheck(t *testing.T) {
	// Setup Mock Remote Server
	remoteCalls := atomic.Int32{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteCalls.Add(1)
		ip := r.URL.Query().Get("ip")
		if ip == "9.9.9.9" {
			w.WriteHeader(http.StatusForbidden) // Blocked
			return
		}
		w.WriteHeader(http.StatusOK) // Allowed
	}))
	defer ts.Close()

	dataDir := createTempDir(t)
	cfg := &alaye.Firewall{
		Enabled:     true,
		RemoteCheck: ts.URL,
	}

	f, err := New(cfg, woos.NewFolder(dataDir), newTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	handler := f.Handler(mockHandler)

	// 1. Test Blocked IP
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "9.9.9.9:1234"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	if w1.Code != http.StatusForbidden {
		t.Error("Remote check failed to block bad IP")
	}

	// 2. Test Allowed IP
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "8.8.8.8:1234"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Error("Remote check blocked good IP")
	}

	if remoteCalls.Load() != 2 {
		t.Errorf("Expected 2 remote calls, got %d", remoteCalls.Load())
	}

	// 3. Test Caching (Repeat request for blocked IP)
	// Should hit cache, NOT increment remoteCalls
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "9.9.9.9:1234"
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)

	if w3.Code != http.StatusForbidden {
		t.Error("Cached check failed to block")
	}

	if remoteCalls.Load() != 2 {
		t.Errorf("Expected cached hit (2 calls total), but got %d", remoteCalls.Load())
	}
}

func TestFirewall_Singleflight(t *testing.T) {
	// This test ensures that concurrent requests for the same IP only trigger ONE remote call
	var calls atomic.Int32
	// Use a latch to ensure concurrency
	startLatch := make(chan struct{})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wait for signal to simulate processing time and force overlap
		<-startLatch
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	dataDir := createTempDir(t)
	cfg := &alaye.Firewall{Enabled: true, RemoteCheck: ts.URL}
	f, _ := New(cfg, woos.NewFolder(dataDir), newTestLogger())
	defer f.Close()

	handler := f.Handler(mockHandler)
	concurrency := 10
	done := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "1.2.3.4:1111"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			done <- struct{}{}
		}()
	}

	// Release the hounds (allow server to respond)
	// We sleep slightly to let goroutines reach the singleflight barrier
	time.Sleep(10 * time.Millisecond)
	close(startLatch)

	// Wait for all to finish
	for i := 0; i < concurrency; i++ {
		<-done
	}

	if calls.Load() != 1 {
		t.Errorf("Expected exactly 1 remote call due to singleflight, got %d", calls.Load())
	}
}

func TestFirewall_Persistence(t *testing.T) {
	dataDir := createTempDir(t)
	cfg := &alaye.Firewall{Enabled: true}

	// 1. Start, add rule, close
	f1, _ := New(cfg, woos.NewFolder(dataDir), newTestLogger())
	if err := f1.Block("5.5.5.5", "persist", 0); err != nil {
		t.Fatal(err)
	}
	f1.Close()

	// 2. Start new instance, verify rule exists
	f2, err := New(cfg, woos.NewFolder(dataDir), newTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "5.5.5.5:1234"
	w := httptest.NewRecorder()
	f2.Handler(mockHandler).ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Error("Persisted rule was lost after restart")
	}
}
