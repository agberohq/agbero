package firewall

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
)

func newTestLogger() *ll.Logger {
	return ll.New("test")
}

func createTempDir(t *testing.T) string {
	dir, err := os.MkdirTemp("", "agbero-firewall-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

var mockHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestFirewall_Specificity(t *testing.T) {
	dataDir := createTempDir(t)
	cfg := &alaye.Firewall{Enabled: true}
	f, _ := New(cfg, woos.NewFolder(dataDir), newTestLogger())
	defer f.Close()

	ip := "1.2.3.4"

	// 1. Block globally
	f.Block(ip, "", "", "global block", 0)

	req := httptest.NewRequest("GET", "http://example.com/api", nil)
	req.RemoteAddr = ip + ":123"
	w := httptest.NewRecorder()
	f.Handler(mockHandler).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Error("Global block failed")
	}

	f.Unblock(ip)

	// 2. Block specific Host
	f.Block(ip, "api.com", "", "host block", 0)

	// Matching host
	req = httptest.NewRequest("GET", "http://api.com/foo", nil)
	req.RemoteAddr = ip + ":123"
	w = httptest.NewRecorder()
	f.Handler(mockHandler).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Error("Host specific block failed on matching host")
	}

	// Different host
	req = httptest.NewRequest("GET", "http://other.com/foo", nil)
	req.RemoteAddr = ip + ":123"
	w = httptest.NewRecorder()
	f.Handler(mockHandler).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Error("Host specific block affected wrong host")
	}

	f.Unblock(ip)

	// 3. Block specific Path
	f.Block(ip, "", "/admin", "path block", 0)

	// Matching path
	req = httptest.NewRequest("GET", "http://any.com/admin/settings", nil)
	req.RemoteAddr = ip + ":123"
	w = httptest.NewRecorder()
	f.Handler(mockHandler).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Error("Path specific block failed on matching path")
	}

	// Non-matching path
	req = httptest.NewRequest("GET", "http://any.com/public", nil)
	req.RemoteAddr = ip + ":123"
	w = httptest.NewRecorder()
	f.Handler(mockHandler).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Error("Path specific block affected wrong path")
	}
}

func TestFirewall_RemoteCheck(t *testing.T) {
	remoteCalls := atomic.Int32{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remoteCalls.Add(1)
		if r.URL.Query().Get("ip") == "9.9.9.9" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	dataDir := createTempDir(t)
	cfg := &alaye.Firewall{Enabled: true, RemoteCheck: ts.URL}
	f, _ := New(cfg, woos.NewFolder(dataDir), newTestLogger())
	defer f.Close()

	handler := f.Handler(mockHandler)

	// Blocked
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "9.9.9.9:1234"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusForbidden {
		t.Error("Remote check failed")
	}

	// Allowed
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "8.8.8.8:1234"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Error("Remote check blocked good IP")
	}

	if remoteCalls.Load() != 2 {
		t.Errorf("Expected 2 calls, got %d", remoteCalls.Load())
	}
}

func TestFirewall_ImportFile(t *testing.T) {
	dataDir := createTempDir(t)
	blockFile := filepath.Join(dataDir, "blocked.txt")
	os.WriteFile(blockFile, []byte("1.2.3.4\n10.0.0.0/24"), woos.FilePerm)

	cfg := &alaye.Firewall{Enabled: true, BlockList: blockFile}
	f, _ := New(cfg, woos.NewFolder(dataDir), newTestLogger())
	defer f.Close()

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	w := httptest.NewRecorder()
	f.Handler(mockHandler).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Error("Imported IP not blocked")
	}
}
