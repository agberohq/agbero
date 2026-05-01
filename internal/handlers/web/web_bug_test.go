package web

import (
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

		// BUG: The PHP request is forwarded without stripping dangerous headers
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
