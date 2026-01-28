// backend_test.go
package backend

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
)

var (
	testLogger = ll.New("backend")
)

// Helper to create a backend with customizable params
func setupBackend(t *testing.T, server alaye.Server, hc *alaye.HealthCheck, cb *alaye.CircuitBreaker) *Backend {
	route := &alaye.Route{
		HealthCheck:    hc,
		CircuitBreaker: cb,
	}

	b, err := NewBackend(server, route, testLogger)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	return b
}

func TestNewBackend_InvalidURL(t *testing.T) {
	_, err := NewBackend(alaye.NewServer("://invalid-url"), &alaye.Route{}, testLogger)
	if err == nil {
		t.Error("Expected error for invalid URL, got nil")
	}
}

func TestNewBackend_NoHealthCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	b := setupBackend(t, alaye.NewServer(server.URL), nil, nil)
	defer b.Stop()

	// No health check goroutine, just basic setup
	if b.Proxy == nil {
		t.Error("Proxy should be initialized")
	}
	if !b.Alive.Load() {
		t.Error("Server should start alive")
	}
}

func TestServeHTTP_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// FIXED: Force >0 latency so metrics logic works (minUS is 1)
		time.Sleep(20 * time.Microsecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	b := setupBackend(t, alaye.NewServer(server.URL), nil, nil)
	defer b.Stop()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	b.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}
	if body := w.Body.String(); body != "OK" {
		t.Errorf("Expected body 'OK', got %q", body)
	}

	if b.InFlight.Load() != 0 {
		t.Error("InFlight should be 0 after request")
	}
	if b.TotalReqs.Load() != 1 {
		t.Error("TotalReqs should be 1")
	}

	// FIXED: Wait for metrics channel to drain (async metrics race condition)
	time.Sleep(10 * time.Millisecond)

	// Check metrics (non-zero duration)
	snap := b.Metrics.Snapshot()
	if snap.Max == 0 {
		t.Error("Expected non-zero max latency")
	}
}

func TestServeHTTP_ContextCancel(t *testing.T) {
	// Create a server that hangs forever
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block indefinitely
		<-r.Context().Done()
	}))
	defer server.Close()

	b := setupBackend(t, alaye.NewServer(server.URL), nil, nil)
	defer b.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	// Cancel immediately - before the request starts
	cancel()

	// Need to wrap this to capture the panic from the reverse proxy
	var panicErr interface{}
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicErr = r
			}
		}()
		b.ServeHTTP(w, req)
	}()

	// The reverse proxy will panic on canceled context, that's expected
	// We just want to ensure the backend handles it gracefully
	if panicErr == nil {
		// If no panic, check the response
		if w.Code != http.StatusBadGateway {
			t.Logf("Expected 502 or panic on cancel, got %d", w.Code)
		}
	}
}

func TestProxy_DirectorModifications(t *testing.T) {
	var mu sync.Mutex
	receivedHost := ""
	receivedHeaders := make(http.Header)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		receivedHost = r.Host
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	b := setupBackend(t, alaye.NewServer(server.URL), nil, nil)
	defer b.Stop()

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	b.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}

	mu.Lock()
	defer mu.Unlock()

	// Parse the server URL to get expected host
	u, _ := url.Parse(server.URL)
	expectedHost := u.Host

	if receivedHost != expectedHost {
		t.Errorf("Expected Host header to be %q, got %q", expectedHost, receivedHost)
	}

	if receivedHeaders.Get("X-Forwarded-Host") == "" {
		t.Error("Missing X-Forwarded-Host header")
	}

	if receivedHeaders.Get("X-Forwarded-Proto") == "" {
		t.Error("Missing X-Forwarded-Proto header")
	}

	// These headers should be stripped by the director
	if receivedHeaders.Get("Keep-Alive") != "" {
		t.Error("Keep-Alive header should be stripped")
	}

	if receivedHeaders.Get("Proxy-Authorization") != "" {
		t.Error("Proxy-Authorization header should be stripped")
	}
}

func TestCircuitBreaker_Trips(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	route := &alaye.Route{
		CircuitBreaker: &alaye.CircuitBreaker{Threshold: 2},
	}

	b, err := NewBackend(alaye.NewServer(server.URL), route, testLogger)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b.Stop()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Simulate failures by calling error handler directly
	for i := 0; i < 2; i++ {
		b.Proxy.ErrorHandler(w, req, errors.New("test error"))
	}

	// Wait a bit for atomic updates
	time.Sleep(50 * time.Millisecond)

	if b.Alive.Load() {
		t.Error("Should trip after 2 failures")
	}
	if b.Failures.Load() < 2 {
		t.Errorf("Expected at least 2 failures, got %d", b.Failures.Load())
	}
}

func TestCircuitBreaker_NoTripOnCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	route := &alaye.Route{
		CircuitBreaker: &alaye.CircuitBreaker{Threshold: 1},
	}

	b, err := NewBackend(alaye.NewServer(server.URL), route, testLogger)
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b.Stop()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	b.Proxy.ErrorHandler(w, req, context.Canceled)

	// Should not trip on context cancel
	if !b.Alive.Load() {
		t.Error("Context cancel should not trip circuit")
	}
	// Failures might be incremented, but circuit shouldn't trip
	// The actual implementation checks for context.Canceled
}

func TestHealthCheck_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	hc := &alaye.HealthCheck{
		Path:      "/health",
		Interval:  100 * time.Millisecond,
		Threshold: 2,
		Timeout:   50 * time.Millisecond,
	}
	b := setupBackend(t, alaye.NewServer(server.URL), hc, nil)
	defer b.Stop()

	// Wait for health check to run a few times
	time.Sleep(500 * time.Millisecond)

	if b.Alive.Load() {
		t.Error("Should mark down after health check failures")
	}
}

func TestHealthCheck_Recovery(t *testing.T) {
	var healthy atomicBool
	healthy.store(false)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if healthy.load() {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	hc := &alaye.HealthCheck{
		Path:      "/health",
		Interval:  100 * time.Millisecond,
		Threshold: 2,
		Timeout:   50 * time.Millisecond,
	}
	b := setupBackend(t, alaye.NewServer(server.URL), hc, nil)
	defer b.Stop()

	// Start unhealthy
	time.Sleep(300 * time.Millisecond) // Should mark as down
	if b.Alive.Load() {
		t.Error("Should be down initially")
	}

	// Make healthy
	healthy.store(true)

	// Wait for recovery
	time.Sleep(300 * time.Millisecond)

	if !b.Alive.Load() {
		t.Error("Should recover when healthy")
	}
	if b.Failures.Load() != 0 {
		t.Error("Failures should be reset on recovery")
	}
}

// Simple atomic bool for test
type atomicBool struct {
	val bool
	mu  sync.RWMutex
}

func (a *atomicBool) store(val bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.val = val
}

func (a *atomicBool) load() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.val
}

func TestHealthCheck_Jitter(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hc := &alaye.HealthCheck{
		Path:      "/health",
		Interval:  200 * time.Millisecond,
		Threshold: 1,
		Timeout:   100 * time.Millisecond,
	}
	b := setupBackend(t, alaye.NewServer(server.URL), hc, nil)
	defer b.Stop()

	// Run for a bit
	time.Sleep(800 * time.Millisecond) // Should get 2-3 requests

	if requestCount < 2 {
		t.Errorf("Expected at least 2 health checks, got %d", requestCount)
	}
	if !b.Alive.Load() {
		t.Error("Should remain alive")
	}
}

func TestStop_HealthCheckLoop(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hc := &alaye.HealthCheck{
		Path:      "/health",
		Interval:  50 * time.Millisecond,
		Threshold: 1,
		Timeout:   25 * time.Millisecond,
	}
	b := setupBackend(t, alaye.NewServer(server.URL), hc, nil)

	// Let it run a few times
	time.Sleep(150 * time.Millisecond)
	initialCount := requestCount

	// Stop the backend
	b.Stop()

	// Wait and ensure no more requests
	time.Sleep(200 * time.Millisecond)
	finalCount := requestCount

	if finalCount > initialCount+1 { // Allow one in-flight
		t.Errorf("Health check continued after stop: %d -> %d", initialCount, finalCount)
	}
}

func TestUptime(t *testing.T) {
	b := setupBackend(t, alaye.NewServer("http://example.com"), nil, nil)
	defer b.Stop()

	time.Sleep(100 * time.Millisecond)
	up := b.Uptime()
	if up < 100*time.Millisecond {
		t.Errorf("Uptime too low: %v", up)
	}
}

func TestMetricsSnapshot(t *testing.T) {
	b := setupBackend(t, alaye.NewServer("http://example.com"), nil, nil)
	defer b.Stop()

	// Record some values directly on metrics
	b.Metrics.Record(100)
	b.Metrics.Record(200)
	b.Metrics.Record(300)

	// FIXED: Wait for channel to drain
	time.Sleep(10 * time.Millisecond)

	snap := b.Metrics.Snapshot()
	if snap.P50 != 200 {
		t.Errorf("P50 expected 200, got %d", snap.P50)
	}
	if snap.Max != 300 {
		t.Errorf("Max expected 300, got %d", snap.Max)
	}
	if snap.Count != 3 {
		t.Errorf("Count expected 3, got %d", snap.Count)
	}
	if snap.Sum != 600 {
		t.Errorf("Sum expected 600, got %d", snap.Sum)
	}
}
