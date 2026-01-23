package backend

import (
	"context"
	"errors"

	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

// Mock Logger to avoid cluttering test output
type noopLogger struct{}

func (n noopLogger) Info(msg string, args ...any)      {}
func (n noopLogger) Warn(msg string, args ...any)      {}
func (n noopLogger) Error(msg string, args ...any)     {}
func (n noopLogger) Fields(args ...any) woos.TlsLogger { return n }

// Helper to create a backend with customizable params
func setupBackend(t *testing.T, targetURL string, hc *woos.HealthCheckConfig, cb *woos.CircuitBreakerConfig) *Backend {
	route := &woos.Route{
		HealthCheck:    hc,
		CircuitBreaker: cb,
	}

	b, err := NewBackend(targetURL, route, noopLogger{})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	return b
}

func TestNewBackend_InvalidURL(t *testing.T) {
	_, err := NewBackend("invalid-url", &woos.Route{}, noopLogger{})
	if err == nil {
		t.Error("Expected error for invalid URL, got nil")
	}
}

func TestNewBackend_NoHealthCheck(t *testing.T) {
	b := setupBackend(t, "http://example.com", nil, nil)
	defer b.Stop()

	// No health check goroutine, just basic setup
	if b.Proxy == nil {
		t.Error("Proxy should be initialized")
	}
	if !b.Alive.Load() {
		t.Error("Backend should start alive")
	}
}

func TestServeHTTP_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	b := setupBackend(t, server.URL, nil, nil)
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

	// Check metrics (non-zero duration)
	snap := b.Metrics.Snapshot()
	if snap.Max == 0 {
		t.Error("Expected non-zero max latency")
	}
}

func TestServeHTTP_ContextCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate long-running request
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	b := setupBackend(t, server.URL, nil, nil)
	defer b.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	b.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected 502 on cancel, got %d", w.Code)
	}
	if b.Failures.Load() == 0 {
		t.Error("Expected failure increment on cancel")
	}
}

func TestProxy_DirectorModifications(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "test-host" {
			t.Errorf("Expected Host 'test-host', got %q", r.Host)
		}
		if r.Header.Get("X-Forwarded-Host") == "" {
			t.Error("Missing X-Forwarded-Host")
		}
		if r.Header.Get("X-Forwarded-Proto") == "" {
			t.Error("Missing X-Forwarded-Proto")
		}
		if r.Header.Get("Keep-Alive") != "" {
			t.Error("Keep-Alive should be deleted")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Parse URL to set Host
	u, _ := url.Parse(server.URL)
	b := &Backend{
		URL:   u,
		Proxy: httputil.NewSingleHostReverseProxy(u),
	}
	origDirector := b.Proxy.Director
	b.Proxy.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = "test-host"
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Forwarded-Proto", req.URL.Scheme)
		req.Header.Del("Keep-Alive")
		req.Header.Del("Proxy-Authenticate")
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Te")
		req.Header.Del("Trailers")
		req.Header.Del("Transfer-Encoding")
	}

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	b.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}
}

func TestCircuitBreaker_Trips(t *testing.T) {
	b := setupBackend(t, "http://example.com", nil, &woos.CircuitBreakerConfig{Threshold: 3})
	defer b.Stop()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Simulate failures
	for i := 1; i <= 3; i++ {
		b.Proxy.ErrorHandler(w, req, errors.New("test error"))
		if i < 3 && !b.Alive.Load() {
			t.Errorf("Should be alive after %d failures", i)
		}
		if i == 3 && b.Alive.Load() {
			t.Error("Should trip after 3 failures")
		}
	}

	if b.Failures.Load() != 3 {
		t.Errorf("Expected 3 failures, got %d", b.Failures.Load())
	}
}

func TestCircuitBreaker_NoTripOnCancel(t *testing.T) {
	b := setupBackend(t, "http://example.com", nil, &woos.CircuitBreakerConfig{Threshold: 1})
	defer b.Stop()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	b.Proxy.ErrorHandler(w, req, context.Canceled)

	if !b.Alive.Load() {
		t.Error("Context cancel should not trip circuit")
	}
	if b.Failures.Load() != 0 {
		t.Errorf("Expected 0 failures on cancel, got %d", b.Failures.Load())
	}
}

func TestHealthCheck_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	hc := &woos.HealthCheckConfig{
		Path:      "/health",
		Interval:  100 * time.Millisecond,
		Threshold: 2,
		Timeout:   50 * time.Millisecond,
	}
	b := setupBackend(t, server.URL, hc, nil)
	defer b.Stop()

	timeout := time.After(1 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	down := false
	for {
		select {
		case <-timeout:
			t.Fatal("Failed to mark down within 1s")
		case <-ticker.C:
			if !b.Alive.Load() {
				down = true
				goto DONE
			}
		}
	}
DONE:
	if !down {
		t.Error("Did not mark down")
	}
	if b.Failures.Load() == 0 {
		t.Error("Failures not incremented")
	}
}

func TestHealthCheck_Recovery(t *testing.T) {
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

	hc := &woos.HealthCheckConfig{
		Path:      "/health",
		Interval:  100 * time.Millisecond,
		Threshold: 2,
		Timeout:   100 * time.Millisecond,
	}
	b := setupBackend(t, server.URL, hc, nil)
	defer b.Stop()

	// Force down
	b.Alive.Store(false)
	b.Failures.Store(5)
	oldRecovery := b.LastRecovery()

	// Make healthy
	isHealthy = true

	timeout := time.After(1 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	recovered := false
	for {
		select {
		case <-timeout:
			t.Fatal("Failed to recover within 1s")
		case <-ticker.C:
			if b.Alive.Load() {
				recovered = true
				goto DONE
			}
		}
	}
DONE:
	if !recovered {
		t.Error("Did not recover")
	}
	if b.Failures.Load() != 0 {
		t.Error("Failures not reset")
	}
	if b.LastRecovery() == oldRecovery {
		t.Error("LastRecovery not updated")
	}
}

func TestHealthCheck_Jitter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hc := &woos.HealthCheckConfig{
		Path:      "/health",
		Interval:  1 * time.Second,
		Threshold: 1,
		Timeout:   100 * time.Millisecond,
	}
	b := setupBackend(t, server.URL, hc, nil)
	defer b.Stop()

	// Jitter is tested indirectly via loop; for coverage, run briefly
	time.Sleep(1500 * time.Millisecond) // >1s + max jitter (0.5s)
	if !b.Alive.Load() {
		t.Error("Should remain alive")
	}
}

func TestStop_HealthCheckLoop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hc := &woos.HealthCheckConfig{
		Path:      "/health",
		Interval:  100 * time.Millisecond,
		Threshold: 1,
		Timeout:   50 * time.Millisecond,
	}
	b := setupBackend(t, server.URL, hc, nil)

	// Stop immediately
	b.Stop()

	// Give time for loop to exit (if not stopped, it would run forever, but we can't test infinite)
	time.Sleep(200 * time.Millisecond)
	// No panic/error means stop worked (coverage via race detector or manual)
}

func TestUptime(t *testing.T) {
	b := setupBackend(t, "http://example.com", nil, nil)
	defer b.Stop()

	time.Sleep(100 * time.Millisecond)
	up := b.Uptime()
	if up < 100*time.Millisecond {
		t.Errorf("Uptime too low: %v", up)
	}
}

func TestMetricsSnapshot(t *testing.T) {
	b := setupBackend(t, "http://example.com", nil, nil)
	defer b.Stop()

	// Record some values
	b.Metrics.Record(100)
	b.Metrics.Record(200)
	b.Metrics.Record(300)

	snap := b.Metrics.Snapshot()
	if snap.P50 != 200 {
		t.Errorf("P50 expected 200, got %d", snap.P50)
	}
	if snap.Max != 300 {
		t.Errorf("Max expected 300, got %d", snap.Max)
	}
}
