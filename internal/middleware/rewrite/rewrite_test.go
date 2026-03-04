package rewrite

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"github.com/olekukonko/ll"
)

var (
	testLogger = ll.New("").Suspend()
)

func TestRewrite(t *testing.T) {

	tests := []struct {
		name          string
		stripPrefixes []string
		rewrites      []alaye.Rewrite
		inputPath     string
		wantPath      string
		wantRewritten bool
	}{
		{
			name:          "No Config",
			stripPrefixes: nil,
			rewrites:      nil,
			inputPath:     "/api/users",
			wantPath:      "/api/users",
			wantRewritten: false,
		},
		{
			name:          "Strip Prefix Match",
			stripPrefixes: []string{"/api"},
			inputPath:     "/api/users",
			wantPath:      "/users",
			wantRewritten: true,
		},
		{
			name:          "Strip Prefix No Match",
			stripPrefixes: []string{"/v1"},
			inputPath:     "/v2/users",
			wantPath:      "/v2/users",
			wantRewritten: false,
		},
		{
			name:          "Strip Prefix Root Result",
			stripPrefixes: []string{"/blog"},
			inputPath:     "/blog",
			wantPath:      "/",
			wantRewritten: true,
		},
		{
			name:          "Strip Prefix Nested",
			stripPrefixes: []string{"/api/v1"},
			inputPath:     "/api/v1/dashboard",
			wantPath:      "/dashboard",
			wantRewritten: true,
		},
		{
			name:          "Strip Prefix Multiple First Match",
			stripPrefixes: []string{"/api", "/api/v1"},
			inputPath:     "/api/v1/users",
			wantPath:      "/v1/users",
			wantRewritten: true,
		},
		{
			name:          "Regex Rewrite Simple",
			stripPrefixes: nil,
			rewrites: []alaye.Rewrite{
				{Pattern: "^/old/(.*)", Target: "/new/$1", Regex: regexp.MustCompile("^/old/(.*)")},
			},
			inputPath:     "/old/page",
			wantPath:      "/new/page",
			wantRewritten: true,
		},
		{
			name:          "Regex Rewrite Capture",
			stripPrefixes: nil,
			rewrites: []alaye.Rewrite{
				{Pattern: "^/users/(\\d+)", Target: "/u/$1", Regex: regexp.MustCompile("^/users/(\\d+)")},
			},
			inputPath:     "/users/123",
			wantPath:      "/u/123",
			wantRewritten: true,
		},
		{
			name:          "Regex No Match",
			stripPrefixes: nil,
			rewrites: []alaye.Rewrite{
				{Pattern: "^/admin", Target: "/hidden", Regex: regexp.MustCompile("^/admin")},
			},
			inputPath:     "/public",
			wantPath:      "/public",
			wantRewritten: false,
		},
		{
			name:          "Regex Invalid Skipped",
			stripPrefixes: nil,
			rewrites: []alaye.Rewrite{
				{Pattern: "^/valid", Target: "/ok", Regex: regexp.MustCompile("^/valid")},
				{Pattern: "^/invalid", Target: "/bad", Regex: nil},
			},
			inputPath:     "/valid/path",
			wantPath:      "/ok/path",
			wantRewritten: true,
		},
		{
			name:          "Order: Strip Then Rewrite",
			stripPrefixes: []string{"/service"},
			rewrites: []alaye.Rewrite{
				{Pattern: "^/v1/(.*)", Target: "/v2/$1", Regex: regexp.MustCompile("^/v1/(.*)")},
			},
			inputPath:     "/service/v1/data",
			wantPath:      "/v2/data",
			wantRewritten: true,
		},
		{
			name:          "Order: Strip Then No Rewrite Match",
			stripPrefixes: []string{"/public"},
			rewrites: []alaye.Rewrite{
				{Pattern: "^/api/(.*)", Target: "/internal/$1", Regex: regexp.MustCompile("^/api/(.*)")},
			},
			inputPath:     "/public/static/file.css",
			wantPath:      "/static/file.css",
			wantRewritten: true,
		},
		{
			name:          "Multiple Strips Not Applied",
			stripPrefixes: []string{"/api", "/v1"},
			inputPath:     "/v1/users",
			wantPath:      "/users",
			wantRewritten: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedPath string
			var receivedHeader string
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedPath = r.URL.Path
				receivedHeader = r.Header.Get("X-Agbero-Rewrite")
				w.WriteHeader(http.StatusOK)
			})

			handler := New(testLogger, tt.stripPrefixes, tt.rewrites)(nextHandler)

			req := httptest.NewRequest("GET", tt.inputPath, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if receivedPath != tt.wantPath {
				t.Errorf("got path %q, want %q", receivedPath, tt.wantPath)
			}

			isRewritten := receivedHeader == "true"
			if isRewritten != tt.wantRewritten {
				t.Errorf("X-Agbero-Rewrite header = %v (%q), want %v", isRewritten, receivedHeader, tt.wantRewritten)
			}
		})
	}
}

func TestRewriteChain(t *testing.T) {

	// Test that multiple middleware in chain work correctly
	middleware1 := New(testLogger, []string{"/api"}, nil)
	middleware2 := New(testLogger, nil, []alaye.Rewrite{
		{Pattern: "^/v1/(.*)", Target: "/v2/$1", Regex: regexp.MustCompile("^/v1/(.*)")},
	})

	var receivedPath string
	var receivedHeader string
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedHeader = r.Header.Get("X-Agbero-Rewrite")
		w.WriteHeader(http.StatusOK)
	})

	handler := middleware1(middleware2(nextHandler))

	req := httptest.NewRequest("GET", "/api/v1/users", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	expected := "/v2/users"
	if receivedPath != expected {
		t.Errorf("chain: got path %q, want %q", receivedPath, expected)
	}
	if receivedHeader != "true" {
		t.Errorf("chain: X-Agbero-Rewrite header = %q, want true", receivedHeader)
	}
}
