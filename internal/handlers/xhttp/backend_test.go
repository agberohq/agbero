package xhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/metrics"
	"github.com/olekukonko/ll"
)

var (
	testLogger = ll.New("backend").Disable()
)

func setupBackend(t *testing.T, server alaye.Server, hc alaye.HealthCheck, cb alaye.CircuitBreaker) (*Backend, *metrics.Registry) {
	route := &alaye.Route{
		HealthCheck:    hc,
		CircuitBreaker: cb,
	}

	registry := metrics.NewRegistry()

	b, err := NewBackend(server, ConfigBackend{
		Route:    route,
		Logger:   testLogger,
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	return b, registry
}

func TestNewBackend_InvalidURL(t *testing.T) {
	_, err := NewBackend(alaye.NewServer("://invalid-url"), ConfigBackend{
		Logger:   testLogger,
		Registry: metrics.NewRegistry(),
	})
	if err == nil {
		t.Error("Expected error for invalid URL, got nil")
	}
}

func TestNewBackend_NoHealthCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	b, _ := setupBackend(t, alaye.NewServer(server.URL), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	if b.Proxy == nil {
		t.Error("Proxy should be initialized")
	}
	if !b.Alive() {
		t.Error("Server should start alive")
	}
}

func TestServeHTTP_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Microsecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	b, _ := setupBackend(t, alaye.NewServer(server.URL), alaye.HealthCheck{}, alaye.CircuitBreaker{})
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

	if b.Activity.InFlight.Load() != 0 {
		t.Error("InFlight should be 0 after request")
	}
	if b.Activity.Requests.Load() != 1 {
		t.Error("Requests should be 1")
	}

	time.Sleep(10 * time.Millisecond)

	snap := b.Activity.Latency.Snapshot()
	if snap.Max == 0 {
		t.Error("Expected non-zero max latency")
	}
}

func TestServeHTTP_ContextCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	b, _ := setupBackend(t, alaye.NewServer(server.URL), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	cancel()

	var panicErr any
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicErr = r
			}
		}()
		b.ServeHTTP(w, req)
	}()

	if panicErr == nil {
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

	b, _ := setupBackend(t, alaye.NewServer(server.URL), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	b.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", w.Code)
	}

	mu.Lock()
	defer mu.Unlock()

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
	if receivedHeaders.Get("Keep-Alive") != "" {
		t.Error("Keep-alive header should be stripped")
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
		CircuitBreaker: alaye.CircuitBreaker{Threshold: 2},
	}

	registry := metrics.NewRegistry()
	b, err := NewBackend(alaye.NewServer(server.URL), ConfigBackend{
		Route:    route,
		Logger:   testLogger,
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b.Stop()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	for range 2 {
		b.Proxy.ErrorHandler(w, req, errors.New("test error"))
	}

	time.Sleep(50 * time.Millisecond)

	if b.Alive() {
		t.Error("Should trip after 2 failures")
	}
	if b.Activity.Failures.Load() < 2 {
		t.Errorf("Expected at least 2 failures, got %d", b.Activity.Failures.Load())
	}
}

func TestCircuitBreaker_NoTripOnCancel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	route := &alaye.Route{
		CircuitBreaker: alaye.CircuitBreaker{Threshold: 1},
	}

	registry := metrics.NewRegistry()
	b, err := NewBackend(alaye.NewServer(server.URL), ConfigBackend{
		Route:    route,
		Logger:   testLogger,
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b.Stop()

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	b.Proxy.ErrorHandler(w, req, context.Canceled)

	if !b.Alive() {
		t.Error("Context cancel should not trip circuit")
	}
}

func TestHealthCheck_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	hc := alaye.HealthCheck{
		Path:      "/health",
		Interval:  100 * time.Millisecond,
		Threshold: 2,
		Timeout:   50 * time.Millisecond,
	}
	b, _ := setupBackend(t, alaye.NewServer(server.URL), hc, alaye.CircuitBreaker{})
	defer b.Stop()

	time.Sleep(500 * time.Millisecond)

	if b.Alive() {
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

	hc := alaye.HealthCheck{
		Enabled:   alaye.Active,
		Path:      "/health",
		Interval:  100 * time.Millisecond,
		Threshold: 2,
		Timeout:   50 * time.Millisecond,
	}
	b, _ := setupBackend(t, alaye.NewServer(server.URL), hc, alaye.CircuitBreaker{})
	defer b.Stop()

	time.Sleep(300 * time.Millisecond)
	if b.Alive() {
		t.Error("Should be down initially")
	}

	healthy.store(true)

	time.Sleep(300 * time.Millisecond)

	if !b.Alive() {
		t.Error("Should recover when healthy")
	}
	if b.Activity.Failures.Load() != 0 {
		t.Error("Failures should be reset on recovery")
	}
}

func TestHealthCheck_Advanced(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("X-Check") != "true" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"status": "OK"}`))
	}))
	defer server.Close()

	hc := alaye.HealthCheck{
		Enabled:        alaye.Active,
		Path:           "/health",
		Method:         "POST",
		Headers:        map[string]string{"X-Check": "true"},
		ExpectedStatus: []int{201},
		ExpectedBody:   `"status": "OK"`,
		Interval:       50 * time.Millisecond,
		Threshold:      1,
		Timeout:        50 * time.Millisecond,
	}

	b, _ := setupBackend(t, alaye.NewServer(server.URL), hc, alaye.CircuitBreaker{})
	defer b.Stop()

	time.Sleep(200 * time.Millisecond)

	if !b.Alive() {
		t.Error("Backend should be healthy with correct advanced check")
	}
}

func TestHealthCheck_Advanced_BodyMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "FAIL"}`))
	}))
	defer server.Close()

	hc := alaye.HealthCheck{
		Enabled:      alaye.Active,
		Path:         "/health",
		ExpectedBody: `"status": "OK"`,
		Interval:     50 * time.Millisecond,
		Threshold:    1,
		Timeout:      50 * time.Millisecond,
	}

	b, _ := setupBackend(t, alaye.NewServer(server.URL), hc, alaye.CircuitBreaker{})
	defer b.Stop()

	time.Sleep(200 * time.Millisecond)

	if b.Alive() {
		t.Error("Backend should be down due to body mismatch")
	}
}

func TestHealthCheck_HostHeader_From_Domains(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "api.example.com" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hc := alaye.HealthCheck{
		Enabled:  alaye.Active,
		Path:     "/",
		Interval: 50 * time.Millisecond,
		Timeout:  50 * time.Millisecond,
	}

	route := &alaye.Route{
		HealthCheck: hc,
	}

	registry := metrics.NewRegistry()
	b, err := NewBackend(alaye.NewServer(server.URL), ConfigBackend{
		Route:    route,
		Domains:  []string{"api.example.com"},
		Logger:   testLogger,
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b.Stop()

	time.Sleep(200 * time.Millisecond)

	if !b.Alive() {
		t.Error("Backend should be alive with correct Host header from domains")
	}
}

func TestHealthCheck_Jitter(t *testing.T) {
	var hits atomic.Int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := alaye.Server{Address: ts.URL, Weight: 1}
	route := &alaye.Route{
		HealthCheck: alaye.HealthCheck{
			Enabled:  alaye.Active,
			Path:     "/",
			Interval: 10 * time.Millisecond,
			Timeout:  50 * time.Millisecond,
		},
	}

	registry := metrics.NewRegistry()
	b, err := NewBackend(cfg, ConfigBackend{
		Route:    route,
		Logger:   ll.New("test").Disable(),
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewBackend error: %v", err)
	}
	defer b.Stop()

	time.Sleep(100 * time.Millisecond)

	if val := hits.Load(); val == 0 {
		t.Error("Expected health check hits, got 0")
	}
}

func TestStop_HealthCheckLoop(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	hc := alaye.HealthCheck{
		Enabled:   alaye.Active,
		Path:      "/health",
		Interval:  50 * time.Millisecond,
		Threshold: 1,
		Timeout:   25 * time.Millisecond,
	}
	b, _ := setupBackend(t, alaye.NewServer(server.URL), hc, alaye.CircuitBreaker{})

	time.Sleep(50 * time.Millisecond)
	b.Stop()

	hitsAtStop := hits.Load()
	time.Sleep(50 * time.Millisecond)

	currentHits := hits.Load()
	if currentHits > hitsAtStop+1 {
		t.Errorf("Health check loop did not stop. Hits went from %d to %d", hitsAtStop, currentHits)
	}
}

func TestUptime(t *testing.T) {
	b, _ := setupBackend(t, alaye.NewServer("http://example.com"), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	time.Sleep(100 * time.Millisecond)
	up := b.Uptime()
	if up < 100*time.Millisecond {
		t.Errorf("Uptime too low: %v", up)
	}
}

func TestActivitySnapshot(t *testing.T) {
	b, _ := setupBackend(t, alaye.NewServer("http://example.com"), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	b.Activity.StartRequest()
	b.Activity.EndRequest(100, false)
	b.Activity.StartRequest()
	b.Activity.EndRequest(200, false)
	b.Activity.StartRequest()
	b.Activity.EndRequest(300, false)

	time.Sleep(10 * time.Millisecond)

	snap := b.Activity.Latency.Snapshot()
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

	if b.Activity.Requests.Load() != 3 {
		t.Errorf("Requests expected 3, got %d", b.Activity.Requests.Load())
	}
	if b.Activity.Failures.Load() != 0 {
		t.Errorf("Failures expected 0, got %d", b.Activity.Failures.Load())
	}
	if b.Activity.InFlight.Load() != 0 {
		t.Errorf("InFlight expected 0, got %d", b.Activity.InFlight.Load())
	}
}

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
