package stash

import (
	"net/http"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
)

func BenchmarkKeyGeneration(b *testing.B) {
	req, _ := http.NewRequest("GET", "https://example.com/api/v1/users/12345?expand=profile&fields=name,email", nil)
	req.Host = "example.com"
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("Accept-Encoding", "gzip")

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Key(req, nil)
	}
}

func BenchmarkKeyGenerationWithScope(b *testing.B) {
	req, _ := http.NewRequest("GET", "https://example.com/api/v1/users/12345?expand=profile&fields=name,email", nil)
	req.Host = "example.com"
	req.Header.Set("Accept-Language", "en-US")
	req.Header.Set("X-Custom", "value")

	scope := []string{"header:X-Custom", "query"}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Key(req, scope)
	}
}

func BenchmarkMemoryStoreSet(b *testing.B) {
	cfg := &Config{
		Driver:     "memory",
		DefaultTTL: 5 * time.Minute,
		MaxItems:   10000,
	}

	store, _ := NewStore(cfg)
	defer store.Close()

	entry := &Entry{
		Body:      []byte("test body"),
		Headers:   http.Header{},
		Status:    http.StatusOK,
		CreatedAt: time.Now(),
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.Set("key", entry, time.Minute)
	}
}

func BenchmarkMemoryStoreGet(b *testing.B) {
	cfg := &Config{
		Driver:     "memory",
		DefaultTTL: 5 * time.Minute,
		MaxItems:   10000,
	}

	store, _ := NewStore(cfg)
	defer store.Close()

	entry := &Entry{
		Body:      []byte("test body"),
		Headers:   http.Header{},
		Status:    http.StatusOK,
		CreatedAt: time.Now(),
	}
	store.Set("key", entry, time.Minute)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		store.Get("key")
	}
}

func BenchmarkTTLPolicyGetTTL(b *testing.B) {
	policy := &alaye.TTLPolicy{
		Enabled: expect.Active,
		Default: expect.Duration(10 * time.Minute),
		ContentType: map[string]expect.Duration{
			"text/html":      expect.Duration(1 * time.Hour),
			"application/js": expect.Duration(30 * time.Minute),
			"image/png":      expect.Duration(24 * time.Hour),
		},
	}
	defaultTTL := 5 * time.Minute
	contentType := "text/html"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = policy.GetTTL(defaultTTL, contentType)
	}
}

func BenchmarkTTLPolicyShouldCacheResponse(b *testing.B) {
	policy := &alaye.TTLPolicy{
		Enabled: expect.Active,
	}
	headers := http.Header{}
	headers.Set("Cache-Control", "max-age=3600")
	status := http.StatusOK

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = policy.ShouldCacheResponse(status, headers)
	}
}

func BenchmarkNilPolicyShouldCacheResponse(b *testing.B) {
	headers := http.Header{}
	headers.Set("Cache-Control", "max-age=3600")
	status := http.StatusOK

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Default behavior when policy is nil
		if status < 200 || status >= 400 {
			_ = false
		}
	}
}
