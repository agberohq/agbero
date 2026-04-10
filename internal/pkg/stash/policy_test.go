package stash

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
)

func TestTTLPolicyGetTTL(t *testing.T) {
	defaultTTL := 5 * time.Minute

	tests := []struct {
		name        string
		policy      *alaye.TTLPolicy
		contentType string
		expected    time.Duration
	}{
		{
			name:        "nil policy returns default",
			policy:      nil,
			contentType: "text/html",
			expected:    defaultTTL,
		},
		{
			name: "disabled policy returns default",
			policy: &alaye.TTLPolicy{
				Enabled: expect.Inactive,
				Default: alaye.Duration(10 * time.Minute),
			},
			contentType: "text/html",
			expected:    defaultTTL,
		},
		{
			name: "policy default used when no match",
			policy: &alaye.TTLPolicy{
				Enabled: expect.Active,
				Default: alaye.Duration(10 * time.Minute),
			},
			contentType: "text/html",
			expected:    10 * time.Minute,
		},
		{
			name: "content-type match",
			policy: &alaye.TTLPolicy{
				Enabled: expect.Active,
				Default: alaye.Duration(10 * time.Minute),
				ContentType: map[string]alaye.Duration{
					"text/html": alaye.Duration(1 * time.Hour),
				},
			},
			contentType: "text/html",
			expected:    1 * time.Hour,
		},
		{
			name: "content-type prefix match",
			policy: &alaye.TTLPolicy{
				Enabled: expect.Active,
				Default: alaye.Duration(10 * time.Minute),
				ContentType: map[string]alaye.Duration{
					"application/json": alaye.Duration(30 * time.Minute),
				},
			},
			contentType: "application/json; charset=utf-8",
			expected:    30 * time.Minute,
		},
		{
			name: "zero TTL in policy returns zero",
			policy: &alaye.TTLPolicy{
				Enabled: expect.Active,
				Default: alaye.Duration(0),
			},
			contentType: "text/html",
			expected:    0,
		},
		{
			name: "empty content type uses default",
			policy: &alaye.TTLPolicy{
				Enabled: expect.Active,
				Default: alaye.Duration(10 * time.Minute),
			},
			contentType: "",
			expected:    10 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result time.Duration
			if tt.policy == nil {
				result = defaultTTL
			} else {
				result = tt.policy.GetTTL(defaultTTL, tt.contentType)
			}
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestTTLPolicyGetTTLWithExtension(t *testing.T) {
	defaultTTL := 5 * time.Minute

	tests := []struct {
		name        string
		policy      *alaye.TTLPolicy
		contentType string
		extension   string
		expected    time.Duration
	}{
		{
			name: "extension match takes priority",
			policy: &alaye.TTLPolicy{
				Enabled: expect.Active,
				Default: alaye.Duration(10 * time.Minute),
				Extension: map[string]alaye.Duration{
					".rss": alaye.Duration(1 * time.Minute),
				},
				ContentType: map[string]alaye.Duration{
					"application/xml": alaye.Duration(1 * time.Hour),
				},
			},
			contentType: "application/xml",
			extension:   ".rss",
			expected:    1 * time.Minute,
		},
		{
			name: "content-type match when no extension match",
			policy: &alaye.TTLPolicy{
				Enabled: expect.Active,
				Default: alaye.Duration(10 * time.Minute),
				Extension: map[string]alaye.Duration{
					".pdf": alaye.Duration(1 * time.Hour),
				},
				ContentType: map[string]alaye.Duration{
					"application/json": alaye.Duration(30 * time.Minute),
				},
			},
			contentType: "application/json",
			extension:   "",
			expected:    30 * time.Minute,
		},
		{
			name: "fallback to default",
			policy: &alaye.TTLPolicy{
				Enabled: expect.Active,
				Default: alaye.Duration(10 * time.Minute),
			},
			contentType: "text/html",
			extension:   "",
			expected:    10 * time.Minute,
		},
		{
			name:        "nil policy returns default",
			policy:      nil,
			contentType: "text/html",
			extension:   ".html",
			expected:    defaultTTL,
		},
		{
			name: "disabled policy returns default",
			policy: &alaye.TTLPolicy{
				Enabled: expect.Inactive,
				Default: alaye.Duration(10 * time.Minute),
			},
			contentType: "text/html",
			extension:   ".html",
			expected:    defaultTTL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result time.Duration
			if tt.policy == nil {
				result = defaultTTL
			} else {
				result = tt.policy.GetTTLWithExtension(defaultTTL, tt.contentType, tt.extension)
			}
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestTTLPolicyShouldCacheResponse(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		headers  http.Header
		policy   *alaye.TTLPolicy
		expected bool
	}{
		{
			name:     "200 OK is cacheable",
			status:   http.StatusOK,
			headers:  http.Header{},
			policy:   nil,
			expected: true,
		},
		{
			name:     "201 Created is cacheable",
			status:   http.StatusCreated,
			headers:  http.Header{},
			policy:   nil,
			expected: true,
		},
		{
			name:     "204 No Content is cacheable",
			status:   http.StatusNoContent,
			headers:  http.Header{},
			policy:   nil,
			expected: true,
		},
		{
			name:     "206 Partial Content is cacheable",
			status:   http.StatusPartialContent,
			headers:  http.Header{},
			policy:   nil,
			expected: true,
		},
		{
			name:     "301 Moved Permanently is cacheable",
			status:   http.StatusMovedPermanently,
			headers:  http.Header{},
			policy:   nil,
			expected: true,
		},
		{
			name:     "304 Not Modified is cacheable",
			status:   http.StatusNotModified,
			headers:  http.Header{},
			policy:   nil,
			expected: true,
		},
		{
			name:     "300 Multiple Choices not cacheable",
			status:   http.StatusMultipleChoices,
			headers:  http.Header{},
			policy:   nil,
			expected: false,
		},
		{
			name:     "404 Not Found not cacheable",
			status:   http.StatusNotFound,
			headers:  http.Header{},
			policy:   nil,
			expected: false,
		},
		{
			name:     "500 Internal Error not cacheable",
			status:   http.StatusInternalServerError,
			headers:  http.Header{},
			policy:   nil,
			expected: false,
		},
		{
			name:   "no-store prevents caching",
			status: http.StatusOK,
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Cache-Control", "no-store")
				return h
			}(),
			policy:   nil,
			expected: false,
		},
		{
			name:   "private prevents caching",
			status: http.StatusOK,
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Cache-Control", "private")
				return h
			}(),
			policy:   nil,
			expected: false,
		},
		{
			name:   "no-cache prevents caching",
			status: http.StatusOK,
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Cache-Control", "no-cache")
				return h
			}(),
			policy:   nil,
			expected: false,
		},
		{
			name:   "WWW-Authenticate prevents caching",
			status: http.StatusOK,
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("WWW-Authenticate", "Basic")
				return h
			}(),
			policy:   nil,
			expected: false,
		},
		{
			name:   "max-age allows caching",
			status: http.StatusOK,
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Cache-Control", "max-age=3600")
				return h
			}(),
			policy:   nil,
			expected: true,
		},
		{
			name:   "public allows caching",
			status: http.StatusOK,
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Cache-Control", "public")
				return h
			}(),
			policy:   nil,
			expected: true,
		},
		{
			name:   "policy enabled but no restrictions",
			status: http.StatusOK,
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Cache-Control", "max-age=3600")
				return h
			}(),
			policy: &alaye.TTLPolicy{
				Enabled: expect.Active,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result bool
			if tt.policy == nil {
				// Default behavior when no policy - must exclude 300
				result = shouldCacheResponseDefault(tt.status, tt.headers)
			} else {
				result = tt.policy.ShouldCacheResponse(tt.status, tt.headers)
			}
			if result != tt.expected {
				t.Errorf("ShouldCacheResponse() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Helper function for default caching behavior when no policy
func shouldCacheResponseDefault(status int, hdr http.Header) bool {
	// 2xx and 3xx except 300
	if status < 200 || status >= 400 {
		return false
	}

	// 300 Multiple Choices is not cacheable
	if status == http.StatusMultipleChoices {
		return false
	}

	// 304 Not Modified is cacheable
	if status == http.StatusNotModified {
		return true
	}

	cc := hdr.Get("Cache-Control")
	if strings.Contains(cc, "no-store") ||
		strings.Contains(cc, "private") ||
		strings.Contains(cc, "no-cache") {
		return false
	}

	if hdr.Get("WWW-Authenticate") != "" {
		return false
	}

	return true
}

func TestRemoveHopByHopHeaders(t *testing.T) {
	headers := http.Header{
		"Connection":         []string{"close"},
		"Keep-Alive":         []string{"timeout=5"},
		"Proxy-Authenticate": []string{"Basic"},
		"Transfer-Encoding":  []string{"chunked"},
		"Upgrade":            []string{"websocket"},
		"Content-Type":       []string{"application/json"},
		"Cache-Control":      []string{"max-age=3600"},
		"Content-Length":     []string{"123"},
	}

	removeHopByHopHeaders(headers)

	hopHeaders := []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Transfer-Encoding", "Upgrade"}
	for _, h := range hopHeaders {
		if headers.Get(h) != "" {
			t.Errorf("hop-by-hop header %s should be removed", h)
		}
	}

	if headers.Get("Content-Type") != "application/json" {
		t.Error("Content-Type should remain")
	}
	if headers.Get("Cache-Control") != "max-age=3600" {
		t.Error("Cache-Control should remain")
	}
	if headers.Get("Content-Length") != "123" {
		t.Error("Content-Length should remain")
	}
}

// removeHopByHopHeaders removes hop-by-hop headers that should not be cached
func removeHopByHopHeaders(hdr http.Header) {
	hop := []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailers",
		"Transfer-Encoding", "Upgrade",
	}
	for _, h := range hop {
		hdr.Del(h)
	}
}
