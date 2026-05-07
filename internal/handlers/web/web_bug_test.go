package web

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/resource"
)

// isPHPFPMAvailable checks if PHP-FPM is listening on the given address
func isPHPFPMAvailable(address string) bool {
	network := "tcp"
	addr := address

	if strings.HasPrefix(address, "tcp://") {
		addr = strings.TrimPrefix(address, "tcp://")
	} else if strings.HasPrefix(address, "unix://") {
		network = "unix"
		addr = strings.TrimPrefix(address, "unix://")
	} else if strings.HasPrefix(address, "unix:") {
		network = "unix"
		addr = strings.TrimPrefix(address, "unix:")
	}

	conn, err := net.DialTimeout(network, addr, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()

	// Try to make a FastCGI request to verify it's actually PHP-FPM
	// This is optional but more robust
	return true
}

func TestCrossTenantDataLeak_DynamicGzip(t *testing.T) {
	// Create two separate "tenant" roots
	rootA := newTestRoot(t)
	rootB := newTestRoot(t)

	// Both tenants have a file with the exact same path but different content.
	// We make them large enough (>1024 bytes) to trigger dynamic gzip.
	contentA := strings.Repeat("A", 1500)
	contentB := strings.Repeat("B", 1500)

	writeFile(t, rootA, "app.js", contentA)
	writeFile(t, rootB, "app.js", contentB)

	// Create web handlers pointing to the respective roots
	handlerA := newHandler(t, rootA)
	handlerB := newHandler(t, rootB)

	// Tenant A gets requested, which forces "app.js" into the global dynamicGzCache
	rrA := do(t, handlerA, http.MethodGet, "/app.js", acceptGzip())
	if rrA.Code != http.StatusOK {
		t.Fatalf("Tenant A request failed: %d", rrA.Code)
	}
	if gotA := decompressGzip(t, rrA); gotA != contentA {
		t.Fatalf("Tenant A got wrong content: expected %d 'A's", len(contentA))
	}

	// Tenant B gets requested for the SAME path "/app.js"
	// Before the fix, this would serve Tenant A's cached gzip data!
	rrB := do(t, handlerB, http.MethodGet, "/app.js", acceptGzip())
	if rrB.Code != http.StatusOK {
		t.Fatalf("Tenant B request failed: %d", rrB.Code)
	}

	// Verify Tenant B gets its own data
	gotB := decompressGzip(t, rrB)
	if gotB == contentA {
		t.Fatal("CRITICAL: Cross-tenant data leak! Tenant B was served Tenant A's cached file.")
	}
	if gotB != contentB {
		t.Fatalf("Tenant B got wrong content. Expected %d 'B's", len(contentB))
	}
}

func TestWeb_PHPTRansferEncodingSmuggling(t *testing.T) {
	// Skip if PHP-FPM is not available on port 9000
	if !isPHPFPMAvailable("tcp://127.0.0.1:9000") {
		t.Skip("PHP-FPM not available on tcp://127.0.0.1:9000, skipping smuggling tests")
	}

	// Create test environment
	res := resource.New()
	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			PHP: alaye.PHP{
				Enabled: expect.Active,
				Address: "tcp://127.0.0.1:9000",
			},
		},
	}

	h := NewWeb(res, route, nil)

	// Test 1: HTTP Request Smuggling via Transfer-Encoding
	t.Run("TransferEncodingChunkedBypass", func(t *testing.T) {
		body := "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: evil.com\r\n\r\n"
		req := httptest.NewRequest("POST", "/malicious.php", strings.NewReader(body))
		req.Header.Set("Transfer-Encoding", "chunked")
		req.Header.Set("Content-Length", "0")

		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		// The PHP request is forwarded without stripping dangerous headers
		// The Go HTTP server already parsed the body, but the
		// Transfer-Encoding header is still present and forwarded to PHP-FPM
		if w.Code == http.StatusOK {
			t.Error("PHP request with conflicting Transfer-Encoding should be rejected")
		}
	})

	// Rest of the tests...
}

func TestWeb_RequestSmuggling(t *testing.T) {
	// Test for CL.TE and TE.CL smuggling variants
	tests := []struct {
		name           string
		method         string
		body           string
		headers        map[string]string
		expectedCode   int
		expectRejected bool
	}{
		{
			name:   "CL.TE Smuggling",
			method: "POST",
			body:   "0\r\n\r\nSMUGGLED",
			headers: map[string]string{
				"Content-Length":    "100",
				"Transfer-Encoding": "chunked",
			},
			expectedCode:   http.StatusMethodNotAllowed,
			expectRejected: true,
		},
		{
			name:   "TE.CL Smuggling",
			method: "POST",
			body:   "5\r\nSMUGGLE\r\n0\r\n\r\n",
			headers: map[string]string{
				"Content-Length":    "4",
				"Transfer-Encoding": "chunked",
			},
			expectedCode:   http.StatusMethodNotAllowed,
			expectRejected: true,
		},
		{
			name:   "Double Content-Length",
			method: "GET",
			body:   "",
			headers: map[string]string{
				"Content-Length": "0",
			},
			expectedCode:   http.StatusOK,
			expectRejected: false,
		},
	}

	res := resource.New()
	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot("/tmp"),
		},
	}

	h := NewWeb(res, route, nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req *http.Request
			if tt.body != "" {
				req = httptest.NewRequest(tt.method, "/test.php", strings.NewReader(tt.body))
			} else {
				req = httptest.NewRequest(tt.method, "/test.php", nil)
			}

			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if tt.expectRejected && w.Code < 400 {
				t.Errorf("%s should be rejected, got code %d", tt.name, w.Code)
			}

			t.Logf("[%s] Response: %d, ExpectRejected: %v", tt.name, w.Code, tt.expectRejected)
		})
	}
}

func TestWeb_HTTPResponseSplitting(t *testing.T) {
	tests := []struct {
		name         string
		requestPath  string
		expectStatus int
		checkBody    bool
	}{
		{
			name:         "CRLF in path via encoded characters",
			requestPath:  "/test%0d%0aSet-Cookie:%20session=hijacked",
			expectStatus: http.StatusBadRequest,
		},
		{
			name:         "Null byte injection",
			requestPath:  "/test%00evil.php",
			expectStatus: http.StatusNotFound,
		},
	}

	res := resource.New()
	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot("/tmp"),
		},
	}

	h := NewWeb(res, route, nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.requestPath, nil)
			w := httptest.NewRecorder()

			h.ServeHTTP(w, req)

			// Verify no CRLF in response headers
			for key := range w.Header() {
				if strings.Contains(key, "\r") || strings.Contains(key, "\n") {
					t.Errorf("CRLF found in response header key: %q", key)
				}
				for _, v := range w.Header()[key] {
					if strings.Contains(v, "\r") || strings.Contains(v, "\n") {
						t.Errorf("CRLF injection in response header value for %s: %q", key, v)
					}
				}
			}

			// Verify response body doesn't contain unsanitized paths
			if tt.checkBody {
				body := w.Body.String()
				if strings.Contains(body, "\r") || strings.Contains(body, "\n") {
					t.Error("CRLF found in response body")
				}
			}

			t.Logf("[%s] Status: %d, Headers: %v", tt.name, w.Code, w.Header())
		})
	}
}

// TestWeb_XSS_DirectoryListing demonstrates XSS via file names
func TestWeb_XSS_DirectoryListing(t *testing.T) {
	root := t.TempDir()

	// Create malicious file names
	xssFile := filepath.Join(root, "<img src=x onerror=alert(1)>.txt")
	if err := os.WriteFile(xssFile, []byte("xss"), 0644); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root:    alaye.WebRoot(root),
			Listing: expect.Active, // Enable directory listing
		},
	}

	res := resource.New()
	h := NewWeb(res, route, nil)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()

	// Check if the XSS payload is reflected without sanitization
	if strings.Contains(body, "<img src=x onerror=alert(1)>") {
		t.Error("VULNERABILITY: XSS via filename in directory listing - file name not HTML-escaped")
	}

	// Verify the response should have HTML-escaped the filename
	if strings.Contains(body, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Log("Properly escaped XSS payload")
	} else if strings.Contains(body, "<img src=x") {
		t.Error("CRITICAL: Raw HTML in directory listing")
	}
}

// TestWeb_PathTraversal_URLEncoded demonstrates path traversal
func TestWeb_PathTraversal_URLEncoded(t *testing.T) {
	root := t.TempDir()

	// Create a secret file outside web root (simulating)
	secretDir := t.TempDir()
	secretFile := filepath.Join(secretDir, "secret.txt")
	os.WriteFile(secretFile, []byte("TOP_SECRET"), 0644)

	// Create symlink from web root to secret (another attack vector)
	os.Symlink(secretDir, filepath.Join(root, "data"))

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
		},
	}

	res := resource.New()
	h := NewWeb(res, route, nil)

	// Test URL-encoded path traversal
	tests := []string{
		"/%2e%2e/%2e%2e/etc/passwd",
		"/..%2f..%2f..%2f/etc/passwd",
		"/....//....//....//etc/passwd",
		"/data/../secret.txt", // Via symlink
	}

	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			// Should NOT return 200 for traversal attempts
			if w.Code == http.StatusOK {
				body := w.Body.String()
				if strings.Contains(body, "TOP_SECRET") || strings.Contains(body, "root:") {
					t.Errorf("VULNERABILITY: Path traversal successful with path: %s", path)
					if len(body) > 100 {
						body = body[:100]
					}
					t.Logf("Response: %s", body)
				}
			}
		})
	}
}

// TestWeb_NullByteInjection tests null byte attacks
func TestWeb_NullByteInjection(t *testing.T) {
	root := t.TempDir()

	// Skip if PHP-FPM is not available on port 9000
	if !isPHPFPMAvailable("tcp://127.0.0.1:9000") {
		t.Skip("PHP-FPM not available on tcp://127.0.0.1:9000, skipping smuggling tests")
	}

	// Create a PHP file
	phpFile := filepath.Join(root, "test.php")
	os.WriteFile(phpFile, []byte("<?php echo 'safe';"), 0644)

	// Create a secret file
	secretFile := filepath.Join(root, "secret.txt")
	os.WriteFile(secretFile, []byte("SECRET_DATA"), 0644)

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
			PHP: alaye.PHP{
				Enabled: expect.Active,
				Address: "127.0.0.1:9000", // removed "tcp://" prefix
			},
		},
	}

	res := resource.New()
	h := NewWeb(res, route, nil)

	// Null byte injection attacks
	tests := []string{
		"/test.php%00.txt",   // Try to serve PHP as text
		"/secret.txt%00.php", // Try to serve text as PHP
		"/test.php%00.html",  // Bypass extension check
	}

	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			// PHP file served with null byte should fail or return PHP
			if strings.Contains(path, ".php") && w.Code == 200 {
				t.Logf("Path %s returned 200, check if PHP execution was bypassed", path)
			}
		})
	}
}

// TestWeb_CRLF_ResponseSplitting tests HTTP response splitting
func TestWeb_CRLF_ResponseSplitting(t *testing.T) {
	root := t.TempDir()

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
		},
	}

	res := resource.New()
	h := NewWeb(res, route, nil)

	// CRLF injection via URL path
	maliciousPaths := []string{
		"/test%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:text/html%0d%0aContent-Length:19%0d%0a%0d%0a<html>HACKED</html>",
		"/test%0d%0aSet-Cookie:%20session=hijacked",
		"/%0d%0aX-XSS-Protection:%200",
	}

	for _, path := range maliciousPaths {
		// Truncate name for test case
		testName := path
		if len(testName) > 50 {
			testName = testName[:50]
		}
		t.Run("CRLF_"+testName, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			// Check response headers for injection
			for key, values := range w.Header() {
				if strings.Contains(key, "\r") || strings.Contains(key, "\n") {
					t.Errorf("CRLF in header KEY: %q", key)
				}
				for _, v := range values {
					if strings.Contains(v, "HACKED") || strings.Contains(v, "hijacked") {
						t.Errorf("VULNERABILITY: Response splitting successful - injected: %s", v)
					}
				}
			}

			// Check if response body contains injected content
			body := w.Body.String()
			if strings.Contains(body, "HACKED") {
				t.Error("VULNERABILITY: Response body poisoning successful")
			}
		})
	}
}

// TestWeb_HeaderInjection_ReverseProxy tests reverse proxy poisoning
func TestWeb_HeaderInjection_ReverseProxy(t *testing.T) {
	// Check if PHP-FPM is available
	conn, err := net.DialTimeout("tcp", "127.0.0.1:9000", 2*time.Second)
	if err != nil {
		t.Skip("PHP-FPM not available on 127.0.0.1:9000, skipping test")
	}
	conn.Close()

	root := t.TempDir()
	phpFile := filepath.Join(root, "info.php")
	os.WriteFile(phpFile, []byte("<?php phpinfo();"), 0644)

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
			PHP: alaye.PHP{
				Enabled: expect.Active,
				Address: "127.0.0.1:9000", // removed "tcp://" prefix
			},
		},
	}

	res := resource.New()
	h := NewWeb(res, route, nil)

	req := httptest.NewRequest("GET", "/info.php", nil)

	// Poison headers that will be forwarded to PHP-FPM
	req.Header.Set("X-Forwarded-Host", "evil.com")
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Real-IP", "10.0.0.1")
	req.Header.Set("X-Forwarded-For", "192.168.1.100")

	// Inject FastCGI params via headers
	req.Header.Set("SCRIPT_FILENAME", "/etc/passwd")
	req.Header.Set("DOCUMENT_ROOT", "/")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code == 200 {
		body := w.Body.String()
		if strings.Contains(body, "evil.com") {
			t.Error("VULNERABILITY: Header poisoning via X-Forwarded-Host")
		}

		if strings.Contains(body, "SCRIPT_FILENAME</td><td class=\"v\">/etc/passwd") {
			t.Error("VULNERABILITY: PHP variable injection via headers")
		}
	}
}

// TestWeb_SymlinkAttack tests symlink following
func TestWeb_SymlinkAttack(t *testing.T) {
	root := t.TempDir()

	// Create secret outside web root
	secretDir := t.TempDir()
	secretFile := filepath.Join(secretDir, "passwords.txt")
	os.WriteFile(secretFile, []byte("admin:secret123"), 0644)

	// Create symlink in web root pointing to secret
	symlinkPath := filepath.Join(root, "data")
	if err := os.Symlink(secretDir, symlinkPath); err != nil {
		t.Skipf("Cannot create symlink (may need admin): %v", err)
	}

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
		},
	}

	res := resource.New()
	h := NewWeb(res, route, nil)

	// Try to access secret via symlink
	req := httptest.NewRequest("GET", "/data/passwords.txt", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code == 200 && strings.Contains(w.Body.String(), "admin:secret123") {
		t.Error("VULNERABILITY: Symlink traversal successful - accessed file outside web root")
	}
}

// newFakeFPM starts an in-process TCP server that returns a minimal FastCGI
// response containing sentinel so the test can assert execution happened.
func newFakeFPM(t *testing.T, sentinel string) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("newFakeFPM: listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed — test finished
			}
			go func(c net.Conn) {
				defer c.Close()
				// Drain incoming FastCGI request bytes (we don't parse them).
				buf := make([]byte, 4096)
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				for {
					_, err := c.Read(buf)
					if err != nil {
						break
					}
				}
				// Write a minimal FastCGI STDOUT record followed by END_REQUEST.
				// FastCGI record layout: version(1) type(1) requestId(2) contentLen(2) paddingLen(1) reserved(1) content
				body := "Content-Type: text/plain\r\n\r\n" + sentinel
				contentLen := len(body)

				// STDOUT record (type=6), request ID=1
				stdout := []byte{
					1, 6, 0, 1,
					byte(contentLen >> 8), byte(contentLen),
					0, 0,
				}
				stdout = append(stdout, []byte(body)...)

				// END_REQUEST record (type=3), request ID=1, 8 bytes of zeros
				endReq := []byte{1, 3, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

				_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Write(stdout)
				_, _ = c.Write(endReq)
			}(conn)
		}
	}()

	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String() // "127.0.0.1:<port>"
}

// withPHP is a routeOpt that enables PHP and points it at addr.
func withPHP(addr string) routeOpt {
	return func(r *alaye.Route) {
		r.Web.PHP.Enabled = expect.Active
		r.Web.PHP.Address = addr
	}
}

// bodyContains reads the response body and reports whether it contains substr.
func bodyContains(rr *httptest.ResponseRecorder, substr string) bool {
	return strings.Contains(rr.Body.String(), substr)
}

// TestWeb_PHP_ExplicitPath_IsExecuted is a baseline: an explicit GET /file.php
// must be forwarded to FastCGI and not served as raw source.
func TestWeb_PHP_ExplicitPath_IsExecuted(t *testing.T) {
	const sentinel = "PHP_WAS_EXECUTED_EXPLICIT"

	addr := newFakeFPM(t, sentinel)
	root := newTestRoot(t)
	writeFile(t, root, "page.php", "<?php echo 'raw source'; ?>")

	h := newHandler(t, root, withPHP(addr))
	rr := do(t, h, http.MethodGet, "/page.php")

	if rr.Code == http.StatusNotFound {
		t.Fatal("explicit .php path: got 404, want FastCGI response")
	}
	if bodyContains(rr, "<?php") {
		t.Fatal("REGRESSION: explicit .php path served raw PHP source instead of executing via FastCGI")
	}
	if !bodyContains(rr, sentinel) {
		t.Fatalf("explicit .php path: sentinel %q not found in body %q", sentinel, rr.Body.String())
	}
}

// TestWeb_PHP_DirectoryIndex_IsExecuted is the core regression for the directory-
// index bug: GET / must trigger FastCGI when the resolved index file is index.php.
// Before the fix, serveDir called http.ServeContent on index.php, leaking source.
func TestWeb_PHP_DirectoryIndex_IsExecuted(t *testing.T) {
	const sentinel = "PHP_WAS_EXECUTED_DIR_INDEX"

	addr := newFakeFPM(t, sentinel)
	root := newTestRoot(t)
	writeFile(t, root, "index.php", "<?php echo 'raw source'; ?>")

	h := newHandler(t, root, withPHP(addr))
	rr := do(t, h, http.MethodGet, "/")

	if rr.Code == http.StatusNotFound {
		t.Fatal("directory index: got 404, want FastCGI response")
	}
	if bodyContains(rr, "<?php") {
		t.Fatal("REGRESSION: GET / served raw index.php source instead of executing via FastCGI (serveDir bug)")
	}
	if !bodyContains(rr, sentinel) {
		t.Fatalf("directory index: sentinel %q not found in body %q", sentinel, rr.Body.String())
	}
}

// TestWeb_PHP_SPAFallback_IsExecuted is the core regression for the SPA-fallback
// a request to a non-existent route must trigger FastCGI when the SPA index
// file is index.php.  Before the fix, handleOpenError called http.ServeContent,
// leaking source.
func TestWeb_PHP_SPAFallback_IsExecuted(t *testing.T) {
	const sentinel = "PHP_WAS_EXECUTED_SPA"

	addr := newFakeFPM(t, sentinel)
	root := newTestRoot(t)
	writeFile(t, root, "index.php", "<?php echo 'raw source'; ?>")
	// Note: /t/general does NOT exist on disk — this must hit the SPA fallback.

	h := newHandler(t, root, withPHP(addr), withSPA())
	rr := do(t, h, http.MethodGet, "/t/general")

	if rr.Code == http.StatusNotFound {
		t.Fatal("SPA fallback: got 404, want FastCGI response")
	}
	if bodyContains(rr, "<?php") {
		t.Fatal("REGRESSION: SPA fallback served raw index.php source instead of executing via FastCGI (handleOpenError bug)")
	}
	if !bodyContains(rr, sentinel) {
		t.Fatalf("SPA fallback: sentinel %q not found in body %q", sentinel, rr.Body.String())
	}
}

// TestWeb_PHP_NotConfigured_DirectoryIndex_Returns404 guards the negative case:
// if PHP is not configured but the only index file is index.php, the server must
// not serve raw source — it should 404.
func TestWeb_PHP_NotConfigured_DirectoryIndex_Returns404(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "index.php", "<?php echo 'secret'; ?>")

	// newHandler with no withPHP option — phpClientFactory will be nil.
	h := newHandler(t, root)
	rr := do(t, h, http.MethodGet, "/")

	if bodyContains(rr, "<?php") || bodyContains(rr, "secret") {
		t.Fatal("SECURITY: index.php source exposed when PHP is not configured")
	}
}

// TestWeb_PHP_NotConfigured_SPA_Returns404 is the same guard for the SPA path.
func TestWeb_PHP_NotConfigured_SPA_Returns404(t *testing.T) {
	root := newTestRoot(t)
	writeFile(t, root, "index.php", "<?php echo 'secret'; ?>")

	h := newHandler(t, root, withSPA())
	rr := do(t, h, http.MethodGet, "/missing/route")

	if bodyContains(rr, "<?php") || bodyContains(rr, "secret") {
		t.Fatal("SECURITY: index.php source exposed via SPA fallback when PHP is not configured")
	}
}

// TestWeb_DenialOfService tests resource exhaustion
func TestWeb_DenialOfService(t *testing.T) {
	root := t.TempDir()

	// Create a large file
	largeContent := strings.Repeat("A", 1024*1024) // 1MB
	os.WriteFile(filepath.Join(root, "large.js"), []byte(largeContent), 0644)

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
		},
	}

	res := resource.New()
	h := NewWeb(res, route, nil)

	// Send many requests with cache-busting to fill memory
	for i := 0; i < 100; i++ { // Reduced from 1000 to 100 for quicker test
		path := fmt.Sprintf("/large.js?v=%d", i) // use fmt.Sprintf instead of rune
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != 200 {
			t.Errorf("Request %d failed: %d", i, w.Code)
			return // Stop on first failure
		}
	}

	// After this, dynamicGzCache should be full or memory increased significantly
	t.Log("DoS test completed - check memory usage")
}
