// internal/core/backend_test.go
package core

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

// Mock Logger to avoid cluttering test output
type noopLogger struct{}

func (n noopLogger) Info(msg string, args ...any)  {}
func (n noopLogger) Warn(msg string, args ...any)  {}
func (n noopLogger) Error(msg string, args ...any) {}
func (n noopLogger) Fields(args ...any) anyLogger  { return n }

// Helper to create a backend
func setupBackend(t *testing.T, targetURL string, threshold int, interval string) *Backend {
	route := &woos.Route{
		HealthCheck: &woos.HealthCheckConfig{
			Path:      "/health",
			Interval:  interval,
			Timeout:   "100ms",
			Threshold: threshold,
		},
		CircuitBreaker: &woos.CircuitBreakerConfig{
			Threshold: threshold,
		},
	}

	b, err := NewBackend(targetURL, route, noopLogger{})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	return b
}

func TestCircuitBreaker_Trips(t *testing.T) {
	// 1. Setup a server that ALWAYS fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// 2. Configure Backend with Threshold = 3
	b := setupBackend(t, server.URL, 3, "1h") // Long interval so background HC doesn't interfere yet
	defer b.Stop()

	// 3. Simulate requests
	// We manually invoke the ErrorHandler because httputil.ReverseProxy handles the networking
	// In a real integration test we would make HTTP requests, but unit testing logic is faster.

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Fail 1
	b.Proxy.ErrorHandler(w, req, http.ErrHandlerTimeout)
	if !b.Alive.Load() {
		t.Error("Backend should still be alive after 1 failure")
	}

	// Fail 2
	b.Proxy.ErrorHandler(w, req, http.ErrHandlerTimeout)
	if !b.Alive.Load() {
		t.Error("Backend should still be alive after 2 failures")
	}

	// Fail 3 (Threshold reached)
	b.Proxy.ErrorHandler(w, req, http.ErrHandlerTimeout)

	if b.Alive.Load() {
		t.Error("Circuit breaker failed to trip after 3 failures")
	}

	if b.Failures.Load() != 3 {
		t.Errorf("Expected 3 failures, got %d", b.Failures.Load())
	}
}

func TestHealthCheck_Recovery(t *testing.T) {
	// 1. Setup Upstream Server
	// Initially unhealthy
	isHealthy := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			if isHealthy {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}))
	defer server.Close()

	// 2. Configure Backend with fast interval
	b := setupBackend(t, server.URL, 2, "100ms")
	defer b.Stop()

	// 3. Manually Trip Circuit to simulate "Down" state
	b.Alive.Store(false)
	b.Failures.Store(5)

	// 4. Make server healthy
	isHealthy = true

	// 5. Wait for Health Check loop to run (Interval is 100ms)
	// We wait up to 1 second
	timeout := time.After(1 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	recovered := false
	for {
		select {
		case <-timeout:
			t.Fatal("Backend failed to recover within 1 second")
		case <-ticker.C:
			if b.Alive.Load() {
				recovered = true
				goto DONE
			}
		}
	}
DONE:

	if !recovered {
		t.Error("Backend did not mark itself Alive")
	}
	if b.Failures.Load() != 0 {
		t.Error("Failures count was not reset")
	}
}
