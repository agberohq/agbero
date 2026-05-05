package web

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/resource"
)

// TestExploit_OpenRedirect_ProtocolRelative proves that protocol-relative
// browserPath is blocked (returns 403) instead of redirecting to attacker.
func TestExploit_OpenRedirect_ProtocolRelative(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0755); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
		},
	}

	res := resource.New()
	h := NewWeb(res, route, nil)

	ctx := context.WithValue(context.Background(), def.CtxOriginalPath, "//evil.com/phish")
	req := httptest.NewRequest("GET", "/docs", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code == http.StatusMovedPermanently {
		loc := w.Header().Get("Location")
		if strings.Contains(loc, "evil.com") {
			t.Errorf("VULNERABILITY: Open redirect via protocol-relative browserPath. Location: %s", loc)
		}
		return
	}

	if w.Code == http.StatusForbidden {
		return
	}

	t.Fatalf("unexpected status %d", w.Code)
}

// TestExploit_StaleGzipCache_TimestampRegression proves that dynamic gzip
// cache does NOT serve stale content when a file is replaced with an older version.
func TestExploit_StaleGzipCache_TimestampRegression(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "stale.txt")
	cacheKey := filePath

	dynamicGzCache.Delete(cacheKey)
	defer dynamicGzCache.Delete(cacheKey)

	contentOld := strings.Repeat("OLD_CONTENT_", 200)
	contentNew := strings.Repeat("NEW_CONTENT_", 200)

	t2020 := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.WriteFile(filePath, []byte(contentOld), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filePath, t2020, t2020); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
		},
	}

	res := resource.New()
	h := NewWeb(res, route, nil)

	req1 := httptest.NewRequest("GET", "/stale.txt", nil)
	req1.Header.Set("Accept-Encoding", "gzip")
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("first request failed: %d", w1.Code)
	}
	if w1.Header().Get("Content-Encoding") != "gzip" {
		t.Skip("dynamic gzip not triggered")
	}

	t2019 := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.WriteFile(filePath, []byte(contentNew), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filePath, t2019, t2019); err != nil {
		t.Fatal(err)
	}

	req2 := httptest.NewRequest("GET", "/stale.txt", nil)
	req2.Header.Set("Accept-Encoding", "gzip")
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("second request failed: %d", w2.Code)
	}

	var body bytes.Buffer
	if w2.Header().Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(w2.Body)
		if err != nil {
			t.Fatalf("gzip.NewReader: %v", err)
		}
		if _, err := body.ReadFrom(gr); err != nil {
			t.Fatalf("gzip read: %v", err)
		}
		gr.Close()
	} else {
		body.Write(w2.Body.Bytes())
	}

	if strings.Contains(body.String(), "OLD_CONTENT") && !strings.Contains(body.String(), "NEW_CONTENT") {
		t.Error("VULNERABILITY: Stale gzip cache served after file replaced with older timestamp")
	}
}

// TestExploit_SymlinkTraversal_OutsideRoot proves symlinks outside root are blocked.
func TestExploit_SymlinkTraversal_OutsideRoot(t *testing.T) {
	root := t.TempDir()

	secretDir := t.TempDir()
	secretFile := filepath.Join(secretDir, "passwords.txt")
	if err := os.WriteFile(secretFile, []byte("admin:secret123"), 0644); err != nil {
		t.Fatal(err)
	}

	symlinkPath := filepath.Join(root, "data")
	if err := os.Symlink(secretDir, symlinkPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
		},
	}

	res := resource.New()
	h := NewWeb(res, route, nil)

	req := httptest.NewRequest("GET", "/data/passwords.txt", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "admin:secret123") {
		t.Error("VULNERABILITY: Symlink traversal allowed access to files outside web root")
	}
}

// TestExploit_ContentDisposition_FilenameCorruption proves semicolons in
// filenames are properly quoted in the Content-Disposition header.
func TestExploit_ContentDisposition_FilenameCorruption(t *testing.T) {
	root := t.TempDir()

	// Semicolon without space — tests RFC 6266 parameter splitting.
	filename := "report;type=html.txt"
	if err := os.WriteFile(filepath.Join(root, filename), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
		},
	}

	res := resource.New()
	h := NewWeb(res, route, nil)

	// Build request manually to avoid httptest.NewRequest URL parsing issues.
	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path:     "/report;type=html.txt",
			RawQuery: "download",
		},
		Header: make(http.Header),
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("request failed: %d", w.Code)
	}

	cd := w.Header().Get("Content-Disposition")
	// Unquoted semicolon causes parameter splitting: filename=report; type=html.txt
	// Quoted form: attachment; filename="report;type=html.txt"
	if strings.Contains(cd, "filename=report;") || !strings.Contains(cd, `"`) {
		t.Errorf("VULNERABILITY: Content-Disposition filename not properly quoted. Header: %s", cd)
	}
}

// TestExploit_PHPHeaderPoisoning proves dangerous headers are stripped before
// reaching PHP-FPM. Skips when PHP-FPM is unavailable.
func TestExploit_PHPHeaderPoisoning(t *testing.T) {
	if !isPHPFPMAvailable("tcp://127.0.0.1:9000") {
		t.Skip("PHP-FPM not available on 127.0.0.1:9000")
	}

	root := t.TempDir()
	phpFile := filepath.Join(root, "dump.php")
	phpSrc := `<?php foreach ($_SERVER as $k => $v) { if (strpos($k, "HTTP_") === 0) echo "$k=$v\n"; }`
	if err := os.WriteFile(phpFile, []byte(phpSrc), 0644); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
			PHP: alaye.PHP{
				Enabled: expect.Active,
				Address: "127.0.0.1:9000",
			},
		},
	}

	res := resource.New()
	h := NewWeb(res, route, nil)

	req := httptest.NewRequest("GET", "/dump.php", nil)
	req.Header.Set("X-Forwarded-Host", "evil.com")
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("X-Real-IP", "10.0.0.1")
	req.Header.Set("X-Forwarded-Proto", "https")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("PHP request failed: %d", w.Code)
	}

	body := w.Body.String()
	if strings.Contains(body, "HTTP_X_FORWARDED_HOST=evil.com") {
		t.Error("VULNERABILITY: X-Forwarded-Host forwarded to PHP-FPM unsanitized")
	}
	if strings.Contains(body, "HTTP_X_REAL_IP=10.0.0.1") {
		t.Error("VULNERABILITY: X-Real-IP forwarded to PHP-FPM unsanitized")
	}
	if strings.Contains(body, "HTTP_X_FORWARDED_PROTO=https") {
		t.Error("VULNERABILITY: X-Forwarded-Proto forwarded to PHP-FPM unsanitized")
	}
}

// TestExploit_PathTraversal_Encoded tests encoded traversal payloads.
func TestExploit_PathTraversal_Encoded(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte("SECRET"), 0644); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
		},
	}

	res := resource.New()
	h := NewWeb(res, route, nil)

	payloads := []string{
		"/%2e%2e/%2e%2e/secret.txt",
		"/..%2f..%2f..%2fsecret.txt",
		"/....//....//....//secret.txt",
	}

	for _, path := range payloads {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "SECRET") {
				t.Errorf("VULNERABILITY: Path traversal succeeded with %s", path)
			}
		})
	}
}

// TestExploit_HiddenFile_Access proves dot-prefixed files are blocked.
func TestExploit_HiddenFile_Access(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git", "config"), []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
		},
	}

	res := resource.New()
	h := NewWeb(res, route, nil)

	req := httptest.NewRequest("GET", "/.git/config", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Error("VULNERABILITY: Hidden file (.git/config) is accessible")
	}
}

// TestExploit_DirectoryListing_XSS checks HTML escaping of filenames.
func TestExploit_DirectoryListing_XSS(t *testing.T) {
	root := t.TempDir()

	xssName := "<img src=x onerror=alert(1)>.txt"
	if err := os.WriteFile(filepath.Join(root, xssName), []byte("xss"), 0644); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root:    alaye.WebRoot(root),
			Listing: expect.Active,
		},
	}

	res := resource.New()
	h := NewWeb(res, route, nil)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	body := w.Body.String()
	if strings.Contains(body, "<img src=x onerror=alert(1)>") {
		t.Error("VULNERABILITY: XSS via unescaped filename in directory listing")
	}
}

// TestExploit_CRLF_ResponseSplitting checks CRLF in browserPath is blocked.
func TestExploit_CRLF_ResponseSplitting(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0755); err != nil {
		t.Fatal(err)
	}

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
		},
	}

	res := resource.New()
	h := NewWeb(res, route, nil)

	ctx := context.WithValue(context.Background(), def.CtxOriginalPath, "/docs\r\nX-Injected: evil")
	req := httptest.NewRequest("GET", "/docs", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Header().Get("X-Injected") != "" {
		t.Error("VULNERABILITY: CRLF in browserPath allowed response header injection")
	}
}

// TestExploit_DynamicGzCache_MemoryPressure verifies no panic or leak under load.
func TestExploit_DynamicGzCache_MemoryPressure(t *testing.T) {
	root := t.TempDir()

	content := strings.Repeat("A", 2048)
	if err := os.WriteFile(filepath.Join(root, "large.txt"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	dynamicGzCache.Delete(filepath.Join(root, "large.txt"))
	defer dynamicGzCache.Delete(filepath.Join(root, "large.txt"))

	route := &alaye.Route{
		Path: "/",
		Web: alaye.Web{
			Root: alaye.WebRoot(root),
		},
	}

	res := resource.New()
	h := NewWeb(res, route, nil)

	for i := 0; i < 100; i++ {
		req := httptest.NewRequest("GET", fmt.Sprintf("/large.txt?v=%d", i), nil)
		req.Header.Set("Accept-Encoding", "gzip")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("request %d failed: %d", i, w.Code)
		}
	}
}
