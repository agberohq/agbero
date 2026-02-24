package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/olekukonko/ll"
)

func TestMain(m *testing.M) {
	logger = ll.New("test").Disable()
}
func TestLoadTester_Basic(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	cfg := LoadConfig{
		Targets:     []string{server.URL},
		Concurrency: 2,
		Requests:    10,
		Method:      "GET",
		Timeout:     5 * time.Second,
	}

	lt := NewLoad(cfg)
	metrics := lt.Run()

	if metrics.Total.Load() != 10 {
		t.Errorf("Expected 10 requests, got %d", metrics.Total.Load())
	}
	if metrics.Success.Load() != 10 {
		t.Errorf("Expected 10 successes, got %d", metrics.Success.Load())
	}
	if metrics.Errors.Load() != 0 {
		t.Errorf("Expected 0 errors, got %d", metrics.Errors.Load())
	}
}

func TestLoadTester_WithFailures(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount%3 == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := LoadConfig{
		Targets:     []string{server.URL},
		Concurrency: 1,
		Requests:    9,
		Method:      "GET",
	}

	lt := NewLoad(cfg)
	metrics := lt.Run()

	if metrics.Errors.Load() != 3 {
		t.Errorf("Expected 3 errors, got %d", metrics.Errors.Load())
	}
}

func TestLoadTester_RateLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := LoadConfig{
		Targets:     []string{server.URL},
		Concurrency: 10,
		Requests:    20,
		RateLimit:   10, // 10 req/sec
		Method:      "GET",
	}

	lt := NewLoad(cfg)
	start := time.Now()
	metrics := lt.Run()
	elapsed := time.Since(start)

	// Should take roughly 2 seconds for 20 requests at 10 req/sec
	// Allow some variance due to burst bucket and timing
	if elapsed < 1*time.Second {
		t.Errorf("Rate limit not working: completed too fast in %v", elapsed)
	}

	// With burst of 10 and rate of 10/sec, 20 requests should complete
	// in roughly 1-2 seconds depending on timing
	if metrics.Total.Load() != 20 {
		t.Errorf("Expected 20 requests, got %d", metrics.Total.Load())
	}
}

func TestLoadTester_Duration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := LoadConfig{
		Targets:     []string{server.URL},
		Concurrency: 2,
		Requests:    0, // Infinite
		Duration:    500 * time.Millisecond,
		Method:      "GET",
	}

	lt := NewLoad(cfg)
	start := time.Now()
	metrics := lt.Run()
	elapsed := time.Since(start)

	if elapsed < 400*time.Millisecond || elapsed > 700*time.Millisecond {
		t.Errorf("Duration not respected: %v", elapsed)
	}
	if metrics.Total.Load() == 0 {
		t.Error("Expected some requests")
	}
}

func TestHistogram(t *testing.T) {
	// NewHistogram now takes buckets slice, nil uses defaults
	h := NewHistogram(true)

	h.Record(5 * time.Millisecond)
	h.Record(25 * time.Millisecond)
	h.Record(75 * time.Millisecond)
	h.Record(200 * time.Millisecond)
	h.Record(600 * time.Millisecond)

	p50 := h.Percentile(50)
	// P50 should be around 25ms or 75ms depending on sorting
	if p50 < 20*time.Millisecond || p50 > 80*time.Millisecond {
		t.Errorf("Unexpected p50: %v (expected ~25-75ms)", p50)
	}

	p95 := h.Percentile(95)
	if p95 < 500*time.Millisecond {
		t.Errorf("Unexpected p95: %v (expected >500ms)", p95)
	}

	mean := h.Mean()
	if mean <= 0 {
		t.Error("Mean should be positive")
	}
	if mean < 100*time.Millisecond || mean > 300*time.Millisecond {
		t.Errorf("Unexpected mean: %v", mean)
	}
}

func TestServerConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ServerConfig
		wantErr bool
	}{
		{
			name:    "valid",
			cfg:     ServerConfig{FailureRate: 0.5, CacheHitRate: 0.5, CPULoad: 0.5},
			wantErr: false,
		},
		{
			name:    "invalid failure rate",
			cfg:     ServerConfig{FailureRate: 1.5},
			wantErr: true,
		},
		{
			name:    "invalid cache rate",
			cfg:     ServerConfig{CacheHitRate: -0.1},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadConfig_Validate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	tests := []struct {
		name    string
		cfg     LoadConfig
		wantErr bool
	}{
		{
			name:    "valid",
			cfg:     LoadConfig{Targets: []string{server.URL}, Concurrency: 1, Requests: 1},
			wantErr: false,
		},
		{
			name:    "no targets",
			cfg:     LoadConfig{Concurrency: 1},
			wantErr: true,
		},
		{
			name:    "invalid URL",
			cfg:     LoadConfig{Targets: []string{"not-a-url"}, Concurrency: 1},
			wantErr: true,
		},
		{
			name:    "zero concurrency",
			cfg:     LoadConfig{Targets: []string{server.URL}, Concurrency: 0},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func BenchmarkLoadTester(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := LoadConfig{
		Targets:     []string{server.URL},
		Concurrency: 10,
		Requests:    b.N,
		Method:      "GET",
	}

	lt := NewLoad(cfg)
	b.ResetTimer()
	lt.Run()
}
