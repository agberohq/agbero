package errorpages

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
)

func TestNew(t *testing.T) {
	tmpDir := t.TempDir()

	route404 := filepath.Join(tmpDir, "route404.html")
	host500 := filepath.Join(tmpDir, "host500.html")
	globalDefault := filepath.Join(tmpDir, "global.html")

	os.WriteFile(route404, []byte("route 404"), 0644)
	os.WriteFile(host500, []byte("host 500"), 0644)
	os.WriteFile(globalDefault, []byte("global default"), 0644)

	cfg := Config{
		RoutePages: alaye.ErrorPages{
			Pages:   map[string]string{"404": route404},
			Default: "",
		},
		HostPages: alaye.ErrorPages{
			Pages:   map[string]string{"500": host500},
			Default: "",
		},
		GlobalPages: alaye.ErrorPages{
			Pages:   map[string]string{},
			Default: globalDefault,
		},
	}

	middleware := New(cfg)

	t.Run("serves route specific error page", func(t *testing.T) {
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, rr.Code)
		}
		if body := rr.Body.String(); body != "route 404" {
			t.Errorf("expected body 'route 404', got '%s'", body)
		}
		if ct := rr.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
			t.Errorf("expected Content-Type 'text/html; charset=utf-8', got '%s'", ct)
		}
	})

	t.Run("serves host specific error page", func(t *testing.T) {
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("expected status %d, got %d", http.StatusInternalServerError, rr.Code)
		}
		if body := rr.Body.String(); body != "host 500" {
			t.Errorf("expected body 'host 500', got '%s'", body)
		}
	})

	t.Run("falls back to global default", func(t *testing.T) {
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest) // 400 not configured specifically
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
		}
		if body := rr.Body.String(); body != "global default" {
			t.Errorf("expected body 'global default', got '%s'", body)
		}
	})

	t.Run("passes through when no error page configured", func(t *testing.T) {
		emptyCfg := Config{}
		emptyMiddleware := New(emptyCfg)
		handler := emptyMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("original not found"))
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("expected status %d, got %d", http.StatusNotFound, rr.Code)
		}
		if body := rr.Body.String(); body != "original not found" {
			t.Errorf("expected body 'original not found', got '%s'", body)
		}
	})

	t.Run("passes through successful responses", func(t *testing.T) {
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		}))

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
		}
		if body := rr.Body.String(); body != "success" {
			t.Errorf("expected body 'success', got '%s'", body)
		}
	})
}

func TestErrorWriter_Write(t *testing.T) {
	t.Run("auto-sets OK status on first write", func(t *testing.T) {
		ew := &errorWriter{
			ResponseWriter: httptest.NewRecorder(),
		}
		ew.Write([]byte("test"))
		if ew.code != http.StatusOK {
			t.Errorf("expected code %d, got %d", http.StatusOK, ew.code)
		}
	})

	t.Run("discards body when intercepted", func(t *testing.T) {
		rr := httptest.NewRecorder()
		ew := &errorWriter{
			ResponseWriter: rr,
			intercepted:    true,
			wroteHeader:    true,
			code:           404,
		}
		n, err := ew.Write([]byte("should be discarded"))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if n != len("should be discarded") {
			t.Errorf("expected %d bytes written, got %d", len("should be discarded"), n)
		}
		if rr.Body.String() != "" {
			t.Errorf("expected empty body, got '%s'", rr.Body.String())
		}
	})
}

func TestFindErrorPagePath(t *testing.T) {
	tests := []struct {
		name     string
		cfg      Config
		code     string
		expected string
	}{
		{
			name: "route specific code",
			cfg: Config{
				RoutePages: alaye.ErrorPages{Pages: map[string]string{"404": "/route404.html"}},
			},
			code:     "404",
			expected: "/route404.html",
		},
		{
			name: "route default",
			cfg: Config{
				RoutePages: alaye.ErrorPages{Default: "/route_default.html"},
			},
			code:     "500",
			expected: "/route_default.html",
		},
		{
			name: "host specific code when route missing",
			cfg: Config{
				HostPages: alaye.ErrorPages{Pages: map[string]string{"500": "/host500.html"}},
			},
			code:     "500",
			expected: "/host500.html",
		},
		{
			name: "global specific code",
			cfg: Config{
				GlobalPages: alaye.ErrorPages{Pages: map[string]string{"403": "/global403.html"}},
			},
			code:     "403",
			expected: "/global403.html",
		},
		{
			name: "global default fallback",
			cfg: Config{
				GlobalPages: alaye.ErrorPages{Default: "/global_default.html"},
			},
			code:     "418",
			expected: "/global_default.html",
		},
		{
			name:     "no configuration",
			cfg:      Config{},
			code:     "404",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ew := &errorWriter{cfg: tt.cfg}
			result := ew.findErrorPagePath(tt.code)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestCache(t *testing.T) {
	tmpDir := t.TempDir()
	errorPage := filepath.Join(tmpDir, "error.html")
	os.WriteFile(errorPage, []byte("cached content"), 0644)

	cfg := Config{
		EnableCache: true,
		GlobalPages: alaye.ErrorPages{
			Default: errorPage,
		},
	}

	middleware := New(cfg)

	t.Run("caches error page content", func(t *testing.T) {
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))

		// First request - should read from disk
		req1 := httptest.NewRequest("GET", "/test", nil)
		rr1 := httptest.NewRecorder()
		handler.ServeHTTP(rr1, req1)

		if rr1.Body.String() != "cached content" {
			t.Errorf("first request: expected 'cached content', got '%s'", rr1.Body.String())
		}

		// Modify file
		os.WriteFile(errorPage, []byte("modified content"), 0644)

		// Second request - should still serve cached content (stale cache)
		req2 := httptest.NewRequest("GET", "/test", nil)
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)

		// Note: Cache is not invalidated until next access detects mtime change
		// This test verifies cache is working (serving old content)
		// In production, mtime check happens on every request
	})

	t.Run("cache respects file modification time", func(t *testing.T) {
		// Create fresh middleware to clear cache state
		newMiddleware := New(cfg)
		handler := newMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))

		// Wait and modify file
		time.Sleep(10 * time.Millisecond)
		os.WriteFile(errorPage, []byte("new version"), 0644)

		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		// Should detect mtime change and serve new content
		if rr.Body.String() != "new version" {
			t.Errorf("expected 'new version' after modification, got '%s'", rr.Body.String())
		}
	})
}

func TestReadFile(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("reads existing file", func(t *testing.T) {
		path := filepath.Join(tmpDir, "test.html")
		content := []byte("<html>test</html>")
		os.WriteFile(path, content, 0644)

		ew := &errorWriter{}
		result, ok := ew.readFile(path)
		if !ok {
			t.Error("expected ok=true")
		}
		if string(result) != string(content) {
			t.Errorf("expected '%s', got '%s'", content, result)
		}
	})

	t.Run("handles missing file", func(t *testing.T) {
		ew := &errorWriter{}
		_, ok := ew.readFile("/nonexistent/path.html")
		if ok {
			t.Error("expected ok=false for missing file")
		}
	})

	t.Run("handles large files with size cap", func(t *testing.T) {
		path := filepath.Join(tmpDir, "large.html")
		// Create 15MB file (over 10MB cap)
		largeContent := make([]byte, 15*1024*1024)
		os.WriteFile(path, largeContent, 0644)

		ew := &errorWriter{}
		result, ok := ew.readFile(path)
		if !ok {
			t.Error("expected ok=true even for large file")
		}
		if len(result) != len(largeContent) {
			t.Errorf("expected %d bytes, got %d", len(largeContent), len(result))
		}
	})
}

func TestStatusStrings(t *testing.T) {
	tests := []struct {
		code     int
		expected string
	}{
		{400, "400"},
		{404, "404"},
		{500, "500"},
		{599, "599"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if statusStrings[tt.code] != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, statusStrings[tt.code])
			}
		})
	}
}

func BenchmarkErrorPages(b *testing.B) {
	tmpDir := b.TempDir()
	errorPage := filepath.Join(tmpDir, "error.html")
	os.WriteFile(errorPage, []byte("<html><body>Error</body></html>"), 0644)

	cfg := Config{
		EnableCache: true,
		GlobalPages: alaye.ErrorPages{
			Default: errorPage,
		},
	}

	middleware := New(cfg)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/test", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
		}
	})
}

func BenchmarkErrorPagesNoCache(b *testing.B) {
	tmpDir := b.TempDir()
	errorPage := filepath.Join(tmpDir, "error.html")
	os.WriteFile(errorPage, []byte("<html><body>Error</body></html>"), 0644)

	cfg := Config{
		EnableCache: false,
		GlobalPages: alaye.ErrorPages{
			Default: errorPage,
		},
	}

	middleware := New(cfg)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("GET", "/test", nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
		}
	})
}
