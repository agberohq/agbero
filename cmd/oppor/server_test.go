package main

import (
	"io"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTestServer_Basic(t *testing.T) {
	cfg := ServerConfig{
		Speed:        "fast",
		ContentMode:  "static",
		ResponseSize: "1KB",
	}
	s := NewServer("9999", cfg)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.handler(w, req)

	resp := w.Result()
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if len(body) < 100 {
		t.Error("Response too small")
	}
}

func TestTestServer_Failure(t *testing.T) {
	cfg := ServerConfig{
		FailureRate:    1.0, // Always fail
		FailureCodes:   []int{503},
		FailurePattern: "random",
	}
	s := NewServer("9998", cfg)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.handler(w, req)

	resp := w.Result()
	if resp.StatusCode != 503 {
		t.Errorf("Expected 503, got %d", resp.StatusCode)
	}
}

func TestTestServer_Session(t *testing.T) {
	cfg := ServerConfig{
		SessionMode: "sticky",
	}
	s := NewServer("9997", cfg)

	// First request - should create session
	req1 := httptest.NewRequest("GET", "/", nil)
	w1 := httptest.NewRecorder()
	s.handler(w1, req1)

	cookies := w1.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("Expected session cookie")
	}

	// Second request with cookie
	req2 := httptest.NewRequest("GET", "/", nil)
	for _, c := range cookies {
		req2.AddCookie(c)
	}
	w2 := httptest.NewRecorder()
	s.handler(w2, req2)

	if w2.Header().Get("X-Session-Active") != "true" {
		t.Error("Expected active session")
	}
}

func TestTestServer_Latency(t *testing.T) {
	cfg := ServerConfig{
		BaseLatency: 50 * time.Millisecond,
		Jitter:      0,
	}
	s := NewServer("9996", cfg)

	start := time.Now()
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.handler(w, req)
	elapsed := time.Since(start)

	if elapsed < 40*time.Millisecond {
		t.Errorf("Latency too short: %v", elapsed)
	}
}

func TestTestServer_Metrics(t *testing.T) {
	cfg := ServerConfig{}
	s := NewServer("9995", cfg)
	s.Requests.Add(100)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	s.metricsHandler(w, req)

	resp := w.Result()
	if resp.StatusCode != 200 {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if len(body) == 0 {
		t.Error("Empty metrics response")
	}
}

func TestCalculateLatency(t *testing.T) {
	tests := []struct {
		name     string
		cfg      ServerConfig
		expected time.Duration
	}{
		{
			name:     "fast",
			cfg:      ServerConfig{Speed: "fast"},
			expected: time.Millisecond,
		},
		{
			name:     "slow with base",
			cfg:      ServerConfig{Speed: "slow", BaseLatency: 50 * time.Millisecond},
			expected: 150 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewServer("9994", tt.cfg)
			latency := s.calculateLatency("/")
			if latency < tt.expected-10*time.Millisecond {
				t.Errorf("Expected ~%v, got %v", tt.expected, latency)
			}
		})
	}
}
