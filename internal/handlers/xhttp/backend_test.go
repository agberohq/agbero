package xhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/agberohq/agbero/internal/pkg/health"
	"github.com/agberohq/agbero/internal/pkg/metrics"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
)

var testLogger = ll.New("backend").Disable()

func setupBackend(t *testing.T, server alaye.Server, hc alaye.HealthCheck, cb alaye.CircuitBreaker) (*Backend, *metrics.Registry, *jack.Doctor) {
	t.Helper()
	route := &alaye.Route{
		Path:           "/",
		HealthCheck:    hc,
		CircuitBreaker: cb,
	}
	testRes := resource.New()
	domain := "example.com"
	statsKey := route.BackendKey(domain, server.Address.String())
	hScore := testRes.Health.GetOrSet(statsKey, health.NewScore(health.DefaultThresholds(), health.DefaultScoringWeights(), health.DefaultLatencyThresholds(), nil))
	b, err := NewBackend(ConfigBackend{
		Server:   server,
		Route:    route,
		Domains:  []string{domain},
		Logger:   testLogger,
		Resource: testRes,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	var doctor *jack.Doctor
	if hc.Enabled.Active() || (hc.Enabled == alaye.Unknown && hc.Path != "") {
		doctor = jack.NewDoctor(jack.DoctorWithLogger(testLogger))
		u, _ := url.Parse(server.Address.String())
		probePath := hc.Path
		if probePath == "" {
			probePath = "/"
		}
		targetURL := u.ResolveReference(&url.URL{Path: probePath}).String()
		headers := http.Header{}
		hostHeader := ""
		for k, v := range hc.Headers {
			if k == "Host" {
				hostHeader = v
			} else {
				headers.Set(k, v)
			}
		}
		if hostHeader == "" {
			hostHeader = domain
		}
		execClient := &http.Client{
			Timeout: hc.Timeout,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 10,
				DisableKeepAlives:   true,
			},
		}
		executor := &HTTPExecutor{
			URL:            targetURL,
			Method:         hc.Method,
			Client:         execClient,
			Header:         headers,
			Host:           hostHeader,
			ExpectedStatus: hc.ExpectedStatus,
			ExpectedBody:   hc.ExpectedBody,
		}
		patient := jack.NewPatient(jack.PatientConfig{
			ID:       statsKey.String(),
			Interval: hc.Interval,
			Timeout:  hc.Timeout,
			Check: func(ctx context.Context) error {
				success, latency, err := executor.Probe(ctx)
				hScore.Update(health.Record{
					ProbeLatency: latency,
					ProbeSuccess: success,
					ConnHealth:   100,
					PassiveRate:  hScore.PassiveErrorRate(),
				})
				if !success {
					if err != nil {
						return err
					}
					return errors.New("probe failed")
				}
				return nil
			},
		})
		_ = doctor.Add(patient)
	}
	return b, testRes.Metrics, doctor
}
func TestConfigBackend_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ConfigBackend
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: ConfigBackend{
				Server:   alaye.NewServer("http://example.com"),
				Resource: resource.New(),
			},
			wantErr: false,
		},
		{
			name: "empty server address",
			cfg: ConfigBackend{
				Server:   alaye.NewServer(""),
				Resource: resource.New(),
			},
			wantErr: true,
		},
		{
			name: "nil resource",
			cfg: ConfigBackend{
				Server:   alaye.NewServer("http://example.com"),
				Resource: nil,
			},
			wantErr: true,
		},
		{
			name: "resource missing metrics",
			cfg: ConfigBackend{
				Server: alaye.NewServer("http://example.com"),
				Resource: func() *resource.Manager {
					r := resource.New()
					r.Metrics = nil
					return r
				}(),
			},
			wantErr: true,
		},
		{
			name: "resource missing health",
			cfg: ConfigBackend{
				Server: alaye.NewServer("http://example.com"),
				Resource: func() *resource.Manager {
					r := resource.New()
					r.Health = nil
					return r
				}(),
			},
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

func TestConfigProxy_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ConfigProxy
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: ConfigProxy{
				Strategy: "round_robin",
				Timeout:  30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "negative timeout",
			cfg: ConfigProxy{
				Timeout: -1 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "zero timeout",
			cfg: ConfigProxy{
				Timeout: 0,
			},
			wantErr: false,
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

func TestNewBackend_InvalidURL(t *testing.T) {
	testRes := resource.New()
	_, err := NewBackend(ConfigBackend{
		Server:   alaye.NewServer("://invalid-url"),
		Logger:   testLogger,
		Resource: testRes,
	})
	if err == nil {
		t.Error("Expected error for invalid URL, got nil")
	}
}

func TestNewBackend_NoResource(t *testing.T) {
	_, err := NewBackend(ConfigBackend{
		Server:   alaye.NewServer("http://example.com"),
		Logger:   testLogger,
		Resource: nil,
	})
	if err == nil {
		t.Error("Expected error for nil resource, got nil")
	}
}

func TestNewBackend_NoHealthCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	b, _, _ := setupBackend(t, alaye.NewServer(server.URL), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	if b.Proxy == nil {
		t.Error("Proxy should be initialized")
	}
	if !b.Alive() {
		t.Error("Server should start alive")
	}
}

func TestNewBackend_NilRoute(t *testing.T) {
	testRes := resource.New()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	b, err := NewBackend(ConfigBackend{
		Server:   alaye.NewServer(server.URL),
		Route:    nil,
		Domains:  []string{"example.com"},
		Logger:   testLogger,
		Resource: testRes,
	})
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()

	if b.Proxy == nil {
		t.Error("Proxy should be initialized")
	}
}

func TestNewBackend_NilLogger(t *testing.T) {
	testRes := resource.New()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	b, err := NewBackend(ConfigBackend{
		Server:   alaye.NewServer(server.URL),
		Route:    &alaye.Route{Path: "/"},
		Domains:  []string{"example.com"},
		Logger:   nil,
		Resource: testRes,
	})
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()

	if b.Proxy == nil {
		t.Error("Proxy should be initialized")
	}
}

func TestNewBackend_EmptyDomains(t *testing.T) {
	testRes := resource.New()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	b, err := NewBackend(ConfigBackend{
		Server:   alaye.NewServer(server.URL),
		Route:    &alaye.Route{Path: "/"},
		Domains:  []string{},
		Logger:   testLogger,
		Resource: testRes,
	})
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()

	if len(b.RouteDomains()) != 0 {
		t.Error("Expected empty route domains")
	}
}

func TestNewBackend_StreamingEnabled(t *testing.T) {
	testRes := resource.New()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	srv := alaye.NewServer(server.URL)
	srv.Streaming.Enabled = alaye.Active
	srv.Streaming.FlushInterval = 50 * time.Millisecond

	b, err := NewBackend(ConfigBackend{
		Server:   srv,
		Route:    &alaye.Route{Path: "/"},
		Domains:  []string{"example.com"},
		Logger:   testLogger,
		Resource: testRes,
	})
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()

	if b.Proxy == nil {
		t.Error("Proxy should be initialized")
	}
}

func TestServeHTTP_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Microsecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	b, _, _ := setupBackend(t, alaye.NewServer(server.URL), alaye.HealthCheck{}, alaye.CircuitBreaker{})
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

	b, _, _ := setupBackend(t, alaye.NewServer(server.URL), alaye.HealthCheck{}, alaye.CircuitBreaker{})
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

func TestServeHTTP_CircuitBreakerOpen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	b, _, _ := setupBackend(t, alaye.NewServer(server.URL), alaye.HealthCheck{}, alaye.CircuitBreaker{Threshold: 2})
	defer b.Stop()

	b.Activity.Failures.Store(3)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 when circuit breaker open, got %d", w.Code)
	}
}

func TestServeHTTP_CircuitBreakerOpen_WithFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	fallbackHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("fallback"))
	})
	fallback := httptest.NewServer(fallbackHandler)
	defer fallback.Close()
	testRes := resource.New()
	route := &alaye.Route{
		Path: "/",
		CircuitBreaker: alaye.CircuitBreaker{
			Threshold: 2,
		},
	}
	statsKey := route.BackendKey("example.com", server.URL)
	hScore := health.NewScore(health.DefaultThresholds(), health.DefaultScoringWeights(), health.DefaultLatencyThresholds(), nil)
	testRes.Health.Set(statsKey, hScore)
	b, err := NewBackend(ConfigBackend{
		Server:   alaye.NewServer(server.URL),
		Route:    route,
		Domains:  []string{"example.com"},
		Logger:   testLogger,
		Resource: testRes,
		Fallback: fallbackHandler,
	})
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	defer b.Stop()
	b.Activity.Failures.Store(3)
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected 503 from fallback, got %d", w.Code)
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

	b, _, _ := setupBackend(t, alaye.NewServer(server.URL), alaye.HealthCheck{}, alaye.CircuitBreaker{})
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

func TestProxy_DirectorModifications_TLS(t *testing.T) {
	var mu sync.Mutex
	receivedProto := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		receivedProto = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	b, _, _ := setupBackend(t, alaye.NewServer(server.URL), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	req := httptest.NewRequest("GET", "/test", nil)
	req.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	b.ServeHTTP(w, req)

	mu.Lock()
	defer mu.Unlock()
	if receivedProto != "https" {
		t.Errorf("Expected X-Forwarded-Proto https, got %q", receivedProto)
	}
}

func TestCircuitBreaker_Trips(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("error"))
	}))
	defer server.Close()

	b, _, _ := setupBackend(t, alaye.NewServer(server.URL), alaye.HealthCheck{}, alaye.CircuitBreaker{Threshold: 2})
	defer b.Stop()

	b.Abort.Disable()
	req := httptest.NewRequest("GET", "/", nil)
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		b.ServeHTTP(w, req)
		if w.Code != http.StatusBadGateway {
			t.Errorf("Request %d: expected 502, got %d", i+1, w.Code)
		}
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

	b, _, _ := setupBackend(t, alaye.NewServer(server.URL), alaye.HealthCheck{}, alaye.CircuitBreaker{Threshold: 1})
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
		Enabled:   alaye.Active,
		Path:      "/health",
		Interval:  50 * time.Millisecond,
		Threshold: 2,
		Timeout:   100 * time.Millisecond,
	}

	b, _, doctor := setupBackend(t, alaye.NewServer(server.URL), hc, alaye.CircuitBreaker{})
	defer b.Stop()
	if doctor != nil {
		defer doctor.StopAll(1 * time.Second)
	}

	time.Sleep(300 * time.Millisecond)
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
		Interval:  50 * time.Millisecond,
		Threshold: 2,
		Timeout:   100 * time.Millisecond,
	}

	b, _, doctor := setupBackend(t, alaye.NewServer(server.URL), hc, alaye.CircuitBreaker{})
	defer b.Stop()
	if doctor != nil {
		defer doctor.StopAll(1 * time.Second)
	}

	time.Sleep(200 * time.Millisecond)
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
		Timeout:        100 * time.Millisecond,
	}

	b, _, doctor := setupBackend(t, alaye.NewServer(server.URL), hc, alaye.CircuitBreaker{})
	defer b.Stop()
	if doctor != nil {
		defer doctor.StopAll(1 * time.Second)
	}

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
		Timeout:      100 * time.Millisecond,
	}

	b, _, doctor := setupBackend(t, alaye.NewServer(server.URL), hc, alaye.CircuitBreaker{})
	defer b.Stop()
	if doctor != nil {
		defer doctor.StopAll(1 * time.Second)
	}

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
		Timeout:  100 * time.Millisecond,
	}

	route := &alaye.Route{
		Path:        "/",
		HealthCheck: hc,
	}

	domain := "api.example.com"
	testRes := resource.New()
	statsKey := route.BackendKey(domain, server.URL)
	hScore := health.NewScore(health.DefaultThresholds(), health.DefaultScoringWeights(), health.DefaultLatencyThresholds(), nil)
	testRes.Health.Set(statsKey, hScore)

	b, err := NewBackend(ConfigBackend{
		Server:   alaye.NewServer(server.URL),
		Route:    route,
		Domains:  []string{domain},
		Logger:   testLogger,
		Resource: testRes,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
	defer b.Stop()

	doctor := jack.NewDoctor(jack.DoctorWithLogger(testLogger))
	defer doctor.StopAll(1 * time.Second)

	u, _ := url.Parse(server.URL)
	executor := &HTTPExecutor{
		URL:    u.String(),
		Method: "GET",
		Client: &http.Client{Timeout: hc.Timeout},
		Host:   domain,
	}
	patient := jack.NewPatient(jack.PatientConfig{
		ID:       statsKey.String(),
		Interval: hc.Interval,
		Timeout:  hc.Timeout,
		Check: func(ctx context.Context) error {
			success, latency, err := executor.Probe(ctx)
			hScore.Update(health.Record{
				ProbeLatency: latency,
				ProbeSuccess: success,
				PassiveRate:  hScore.PassiveErrorRate(),
				ConnHealth:   100,
			})
			if !success {
				if err != nil {
					return err
				}
				return errors.New("probe failed")
			}
			return nil
		},
	})
	_ = doctor.Add(patient)

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

	hc := alaye.HealthCheck{
		Enabled:  alaye.Active,
		Path:     "/",
		Interval: 20 * time.Millisecond,
		Timeout:  100 * time.Millisecond,
	}

	b, _, doctor := setupBackend(t, alaye.NewServer(ts.URL), hc, alaye.CircuitBreaker{})
	defer b.Stop()
	if doctor != nil {
		defer doctor.StopAll(1 * time.Second)
	}

	time.Sleep(150 * time.Millisecond)
	if val := hits.Load(); val == 0 {
		t.Errorf("Expected health check hits, got %d", val)
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
		Timeout:   100 * time.Millisecond,
	}

	b, _, doctor := setupBackend(t, alaye.NewServer(server.URL), hc, alaye.CircuitBreaker{})
	time.Sleep(100 * time.Millisecond)

	if doctor != nil {
		doctor.StopAll(1 * time.Second)
	}
	b.Stop()

	hitsAtStop := hits.Load()
	time.Sleep(100 * time.Millisecond)
	currentHits := hits.Load()

	if currentHits > hitsAtStop+1 {
		t.Errorf("Health check loop did not stop. Hits went from %d to %d", hitsAtStop, currentHits)
	}
}

func TestUptime(t *testing.T) {
	b, _, _ := setupBackend(t, alaye.NewServer("http://example.com"), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	time.Sleep(100 * time.Millisecond)
	up := b.Uptime()
	if up < 100*time.Millisecond {
		t.Errorf("Uptime too low: %v", up)
	}
}

func TestLastRecovery(t *testing.T) {
	b, _, _ := setupBackend(t, alaye.NewServer("http://example.com"), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	recovery := b.LastRecovery()
	if recovery.IsZero() {
		t.Error("Expected non-zero last recovery time")
	}
}

func TestStatus_Down(t *testing.T) {
	b, _, _ := setupBackend(t, alaye.NewServer("http://example.com"), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	b.Status(false)

	if b.Alive() {
		t.Error("Expected backend to be dead after Status(false)")
	}
	if b.Activity.Failures.Load() < uint64(b.CBThreshold+1) {
		t.Error("Expected failures to be set above threshold")
	}
}

func TestStatus_Up(t *testing.T) {
	b, _, _ := setupBackend(t, alaye.NewServer("http://example.com"), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	b.Status(false)
	b.Status(true)

	if !b.Alive() {
		t.Error("Expected backend to be alive after Status(true)")
	}
	if b.Activity.Failures.Load() != 0 {
		t.Error("Expected failures to be reset to 0")
	}
}

func TestWeight(t *testing.T) {
	b, _, _ := setupBackend(t, alaye.NewServer("http://example.com"), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	weight := b.Weight()
	if weight < 1 {
		t.Errorf("Expected weight >= 1, got %d", weight)
	}
}

func TestWeight_HealthAdjusted(t *testing.T) {
	b, _, _ := setupBackend(t, alaye.NewServer("http://example.com"), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	b.HealthScore.Update(health.Record{
		ProbeSuccess: false,
		ConnHealth:   50,
	})

	weight := b.Weight()
	if weight >= b.WeightVal {
		t.Errorf("Expected weight to be reduced due to health, got %d", weight)
	}
}

func TestInFlight(t *testing.T) {
	b, _, _ := setupBackend(t, alaye.NewServer("http://example.com"), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	b.Activity.StartRequest()
	b.Activity.StartRequest()

	if b.InFlight() != 2 {
		t.Errorf("Expected in-flight 2, got %d", b.InFlight())
	}
}

func TestResponseTime_NoData(t *testing.T) {
	b, _, _ := setupBackend(t, alaye.NewServer("http://example.com"), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	rt := b.ResponseTime()
	if rt != 0 {
		t.Errorf("Expected response time 0 with no data, got %d", rt)
	}
}

func TestResponseTime_WithData(t *testing.T) {
	b, _, _ := setupBackend(t, alaye.NewServer("http://example.com"), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	b.Activity.EndRequest(100, false)
	b.Activity.EndRequest(200, false)
	b.Activity.EndRequest(300, false)

	rt := b.ResponseTime()
	if rt == 0 {
		t.Error("Expected non-zero response time with data")
	}
}

func TestDrain(t *testing.T) {
	b, _, _ := setupBackend(t, alaye.NewServer("http://example.com"), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	b.Activity.StartRequest()

	go func() {
		time.Sleep(50 * time.Millisecond)
		b.Activity.EndRequest(100, false)
	}()

	b.Drain(1 * time.Second)

	if b.Activity.InFlight.Load() != 0 {
		t.Error("Expected in-flight to be 0 after drain")
	}
}

func TestDrain_Timeout(t *testing.T) {
	b, _, _ := setupBackend(t, alaye.NewServer("http://example.com"), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	b.Activity.StartRequest()

	start := time.Now()
	b.Drain(50 * time.Millisecond)
	elapsed := time.Since(start)

	if elapsed < 50*time.Millisecond {
		t.Error("Expected drain to wait for timeout")
	}
}

func TestActivitySnapshot(t *testing.T) {
	testRes := resource.New()
	route := &alaye.Route{Path: "/"}
	statsKey := route.BackendKey("example.com", "http://example.com")
	hScore := health.NewScore(health.DefaultThresholds(), health.DefaultScoringWeights(), health.DefaultLatencyThresholds(), nil)
	testRes.Health.Set(statsKey, hScore)

	b, err := NewBackend(ConfigBackend{
		Server:   alaye.NewServer("http://example.com"),
		Route:    route,
		Domains:  []string{"example.com"},
		Logger:   testLogger,
		Resource: testRes,
	})
	if err != nil {
		t.Fatalf("Failed to create backend: %v", err)
	}
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

func TestBackend_ConcurrentOperations(t *testing.T) {
	b, _, _ := setupBackend(t, alaye.NewServer("http://example.com"), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			b.Status(true)
			b.Status(false)
			b.Alive()
			b.Weight()
			b.InFlight()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
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
