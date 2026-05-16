package xhttp

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/fcgi"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/hub/resource"
)

// startFastCGIServer launches a FastCGI server on a random TCP port using
// Go's standard net/http/fcgi package. Returns the listener address and
// registers cleanup via t.Cleanup.
func startFastCGIServer(t *testing.T, h http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fcgi listen: %v", err)
	}
	go func() { _ = fcgi.Serve(ln, h) }()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// startFastCGIUnixServer launches a FastCGI server on a UNIX socket.
func startFastCGIUnixServer(t *testing.T, h http.Handler) string {
	t.Helper()
	path := t.TempDir() + "/fcgi.sock"
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("fcgi unix listen: %v", err)
	}
	go func() { _ = fcgi.Serve(ln, h) }()
	t.Cleanup(func() { ln.Close() })
	return path
}

func newFastCGIBackendForTest(t *testing.T, addr string) *Backend {
	t.Helper()
	res := resource.New()
	b, err := NewBackend(ConfigBackend{
		Server:   alaye.NewServer(addr),
		Route:    &alaye.Route{Path: "/"},
		Domains:  []string{"example.com"},
		Resource: res,
	})
	if err != nil {
		t.Fatalf("NewBackend(%q): %v", addr, err)
	}
	t.Cleanup(b.Stop)
	return b
}

// Construction / validation

func TestNewBackend_FastCGI_TCP(t *testing.T) {
	addr := startFastCGIServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	b := newFastCGIBackendForTest(t, "cgi://"+addr)

	if b.FastCGI == nil {
		t.Fatal("FastCGI handler should be non-nil for cgi:// backend")
	}
	if b.Proxy != nil {
		t.Fatal("Proxy should be nil for cgi:// backend")
	}
	if !b.Alive() {
		t.Error("backend should start alive")
	}
}

func TestNewBackend_FastCGI_Unix(t *testing.T) {
	sockPath := startFastCGIUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	b := newFastCGIBackendForTest(t, "cgi://unix:"+sockPath)

	if b.FastCGI == nil {
		t.Fatal("FastCGI handler should be non-nil for cgi://unix: backend")
	}
	if b.Proxy != nil {
		t.Fatal("Proxy should be nil for cgi://unix: backend")
	}
}

func TestNewBackend_FastCGI_MissingHost(t *testing.T) {
	res := resource.New()
	_, err := NewBackend(ConfigBackend{
		Server:   alaye.NewServer("cgi://"),
		Route:    &alaye.Route{Path: "/"},
		Resource: res,
	})
	if err == nil {
		t.Fatal("expected error for cgi:// with no host")
	}
}

func TestNewBackend_FastCGI_BadSchemeStillRejected(t *testing.T) {
	res := resource.New()
	_, err := NewBackend(ConfigBackend{
		Server:   alaye.NewServer("ftp://127.0.0.1:21"),
		Route:    &alaye.Route{Path: "/"},
		Resource: res,
	})
	if err == nil {
		t.Fatal("expected error for unsupported scheme ftp://")
	}
}

// Health check registration — regression tests for the initHealth fix
//
// Before the fix, newFastCGIBackend never called initHealth. Any health_check
// block on a cgi:// backend was silently ignored: HasProber was true (computed
// correctly from the route config) but no prober was ever registered with the
// Doctor, so the backend stayed permanently Healthy regardless of upstream state.

// TestFastCGI_HealthCheck_Registered is the direct regression test for the
// missing initHealth call. It verifies that a cgi:// backend with an explicit
// health_check block actually registers a patient with the Doctor.
//
// Before the fix: HasProber == true but Doctor.Metrics().PatientsTotal == 0.
// After the fix:  both HasProber == true and PatientsTotal >= 1.
func TestFastCGI_HealthCheck_Registered(t *testing.T) {
	addr := startFastCGIServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	res := resource.New()
	b, err := NewBackend(ConfigBackend{
		Server:   alaye.NewServer("cgi://" + addr),
		Domains:  []string{"example.com"},
		Resource: res,
		Route: &alaye.Route{
			Path: "/",
			HealthCheck: alaye.HealthCheck{
				Enabled:  expect.Active,
				Path:     "/health",
				Interval: expect.Duration(50 * time.Millisecond),
				Timeout:  expect.Duration(200 * time.Millisecond),
			},
		},
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	defer b.Stop()

	if !b.HasProber {
		t.Fatal("HasProber should be true when health_check.enabled = true")
	}

	if res.Doctor == nil {
		t.Fatal("resource.Doctor is nil")
	}
	// PatientsTotal is incremented by Doctor.Add() inside initHealth.
	// Before the fix initHealth was never called so this stayed at 0.
	if got := res.Doctor.Metrics().PatientsTotal.Load(); got == 0 {
		t.Fatal("no patients registered with Doctor — initHealth was not called on the FastCGI backend (regression)")
	}
}

// TestFastCGI_HealthCheck_NotRegistered_WhenDisabled verifies that when
// health_check is explicitly disabled, HasProber is false and no patient is
// registered with the Doctor.
func TestFastCGI_HealthCheck_NotRegistered_WhenDisabled(t *testing.T) {
	addr := startFastCGIServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	res := resource.New()
	b, err := NewBackend(ConfigBackend{
		Server:   alaye.NewServer("cgi://" + addr),
		Domains:  []string{"example.com"},
		Resource: res,
		Route: &alaye.Route{
			Path: "/",
			HealthCheck: alaye.HealthCheck{
				Enabled: expect.Inactive,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	defer b.Stop()

	if b.HasProber {
		t.Error("HasProber should be false when health_check is disabled")
	}
	if res.Doctor != nil {
		if got := res.Doctor.Metrics().PatientsTotal.Load(); got != 0 {
			t.Errorf("PatientsTotal should be 0 when health_check is disabled, got %d", got)
		}
	}
}

// TestFastCGI_HealthCheck_ImplicitEnable verifies that a health_check block
// with only a path set (Enabled == Unknown) still activates the prober, since
// configuring a path is an implicit opt-in — matching the behaviour of HTTP backends.
func TestFastCGI_HealthCheck_ImplicitEnable(t *testing.T) {
	addr := startFastCGIServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	res := resource.New()
	b, err := NewBackend(ConfigBackend{
		Server:   alaye.NewServer("cgi://" + addr),
		Domains:  []string{"example.com"},
		Resource: res,
		Route: &alaye.Route{
			Path: "/",
			HealthCheck: alaye.HealthCheck{
				Enabled: expect.Unknown,
				Path:    "/ping",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}
	defer b.Stop()

	if !b.HasProber {
		t.Error("HasProber should be true when path is configured with Enabled == Unknown")
	}
	if res.Doctor == nil {
		t.Fatal("resource.Doctor is nil")
	}
	if got := res.Doctor.Metrics().PatientsTotal.Load(); got == 0 {
		t.Error("patient should be registered for implicit health check enable")
	}
}

// TestFastCGI_HealthCheck_Parity verifies that HTTP and FastCGI backends
// register health probers identically when given the same health_check config.
// Before the fix, FastCGI always had PatientsTotal == 0 while HTTP had 1.
func TestFastCGI_HealthCheck_Parity(t *testing.T) {
	hc := alaye.HealthCheck{
		Enabled:  expect.Active,
		Path:     "/health",
		Interval: expect.Duration(100 * time.Millisecond),
		Timeout:  expect.Duration(500 * time.Millisecond),
	}

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpSrv.Close()

	resHTTP := resource.New()
	httpB, err := NewBackend(ConfigBackend{
		Server:   alaye.NewServer(httpSrv.URL),
		Domains:  []string{"example.com"},
		Resource: resHTTP,
		Route:    &alaye.Route{Path: "/", HealthCheck: hc},
	})
	if err != nil {
		t.Fatalf("HTTP NewBackend: %v", err)
	}
	defer httpB.Stop()

	fcgiAddr := startFastCGIServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	resFCGI := resource.New()
	fcgiB, err := NewBackend(ConfigBackend{
		Server:   alaye.NewServer("cgi://" + fcgiAddr),
		Domains:  []string{"example.com"},
		Resource: resFCGI,
		Route:    &alaye.Route{Path: "/", HealthCheck: hc},
	})
	if err != nil {
		t.Fatalf("FastCGI NewBackend: %v", err)
	}
	defer fcgiB.Stop()

	if httpB.HasProber != fcgiB.HasProber {
		t.Errorf("HasProber mismatch: HTTP=%v FastCGI=%v", httpB.HasProber, fcgiB.HasProber)
	}

	httpPatients := resHTTP.Doctor.Metrics().PatientsTotal.Load()
	fcgiPatients := resFCGI.Doctor.Metrics().PatientsTotal.Load()

	if httpPatients == 0 {
		t.Error("HTTP backend: no patients registered with Doctor")
	}
	if fcgiPatients == 0 {
		t.Error("FastCGI backend: no patients registered with Doctor — initHealth not called (regression)")
	}
	if httpPatients != fcgiPatients {
		t.Errorf("patient count mismatch: HTTP=%d FastCGI=%d", httpPatients, fcgiPatients)
	}
}

// Request forwarding

func TestFastCGI_ServeHTTP_BasicRequest(t *testing.T) {
	addr := startFastCGIServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello from fcgi"))
	}))

	b := newFastCGIBackendForTest(t, "cgi://"+addr)
	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "hello from fcgi") {
		t.Errorf("unexpected body: %q", w.Body.String())
	}
}

func TestFastCGI_ServeHTTP_MethodAndPath(t *testing.T) {
	var gotMethod, gotPath, gotQuery string
	addr := startFastCGIServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		// net/http/fcgi reconstructs the request from CGI params; it populates
		// r.URL.Path (from PATH_INFO / SCRIPT_NAME) and r.URL.RawQuery (from
		// QUERY_STRING) but leaves r.RequestURI empty.
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))

	b := newFastCGIBackendForTest(t, "cgi://"+addr)
	b.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/items?foo=bar", nil))

	if gotMethod != http.MethodPost {
		t.Errorf("expected POST, got %q", gotMethod)
	}
	if gotPath != "/api/v1/items" {
		t.Errorf("expected path /api/v1/items, got %q", gotPath)
	}
	if gotQuery != "foo=bar" {
		t.Errorf("expected query foo=bar, got %q", gotQuery)
	}
}

// Header separation — core security invariant

// TestFastCGI_HeaderSeparation verifies that a client-supplied header named
// "Remote-Addr" cannot poison the backend's REMOTE_ADDR. Under FastCGI, client
// HTTP headers arrive with the HTTP_ prefix (HTTP_REMOTE_ADDR), which is a
// completely different namespace from the proxy-set REMOTE_ADDR param.
func TestFastCGI_HeaderSeparation(t *testing.T) {
	var gotRemoteAddr string
	addr := startFastCGIServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRemoteAddr = r.RemoteAddr
		w.WriteHeader(http.StatusOK)
	}))

	b := newFastCGIBackendForTest(t, "cgi://"+addr)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Remote-Addr", "1.3.3.7") // attacker-controlled header
	req.RemoteAddr = "192.168.1.1:54321"
	b.ServeHTTP(httptest.NewRecorder(), req)

	if gotRemoteAddr == "1.3.3.7" {
		t.Error("REMOTE_ADDR was poisoned by client-supplied Remote-Addr header")
	}
}

// Trusted params injected by fcgiBuildTrusted

// TestFastCGI_TrustedParams_PlainHTTP verifies HTTPS is absent and
// SERVER_SOFTWARE is set for a plain HTTP request.
func TestFastCGI_TrustedParams_PlainHTTP(t *testing.T) {
	var gotTLS bool
	var gotSoftware string
	addr := startFastCGIServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTLS = r.TLS != nil
		gotSoftware = fcgi.ProcessEnv(r)["SERVER_SOFTWARE"]
		w.WriteHeader(http.StatusOK)
	}))

	b := newFastCGIBackendForTest(t, "cgi://"+addr)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	b.ServeHTTP(httptest.NewRecorder(), req)

	if gotTLS {
		t.Error("r.TLS should be nil on the backend for a plain HTTP request")
	}
	if !strings.Contains(gotSoftware, def.Name) {
		t.Errorf("SERVER_SOFTWARE should contain %q, got %q", def.Name, gotSoftware)
	}
	if !strings.Contains(gotSoftware, "fastcgi") {
		t.Errorf("SERVER_SOFTWARE should contain 'fastcgi', got %q", gotSoftware)
	}
}

// TestFastCGI_TrustedParams_TLS verifies that when the proxy terminates TLS
// (r.TLS != nil), the backend receives HTTPS=on.
func TestFastCGI_TrustedParams_TLS(t *testing.T) {
	var gotTLS bool
	addr := startFastCGIServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTLS = r.TLS != nil
		w.WriteHeader(http.StatusOK)
	}))

	b := newFastCGIBackendForTest(t, "cgi://"+addr)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.TLS = &tls.ConnectionState{}
	b.ServeHTTP(httptest.NewRecorder(), req)

	if !gotTLS {
		t.Error("expected backend r.TLS to be non-nil when proxy sets HTTPS=on")
	}
}

// TestFastCGI_TrustedParams_ListenerCtx verifies that SERVER_PORT is taken
// from ListenerCtx when available.
func TestFastCGI_TrustedParams_ListenerCtx(t *testing.T) {
	var gotPort string
	addr := startFastCGIServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPort = fcgi.ProcessEnv(r)["SERVER_PORT"]
		w.WriteHeader(http.StatusOK)
	}))

	b := newFastCGIBackendForTest(t, "cgi://"+addr)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := context.WithValue(req.Context(), woos.ListenerCtxKey, woos.ListenerCtx{Port: "8443"})
	req = req.WithContext(ctx)
	b.ServeHTTP(httptest.NewRecorder(), req)

	if gotPort != "8443" {
		t.Errorf("expected SERVER_PORT=8443 from ListenerCtx, got %q", gotPort)
	}
}

// WebSocket rejection

func TestFastCGI_WebSocket_Rejected(t *testing.T) {
	addr := startFastCGIServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	b := newFastCGIBackendForTest(t, "cgi://"+addr)
	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	w := httptest.NewRecorder()
	b.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected 501 for WebSocket on cgi:// backend, got %d", w.Code)
	}
}

// TestFastCGI_WebSocket_CaseInsensitive verifies that WebSocket rejection works
// regardless of Upgrade header casing (strings.EqualFold fix).
func TestFastCGI_WebSocket_CaseInsensitive(t *testing.T) {
	addr := startFastCGIServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	b := newFastCGIBackendForTest(t, "cgi://"+addr)

	for _, upgradeVal := range []string{"websocket", "WebSocket", "WEBSOCKET", "WebSoCkEt"} {
		req := httptest.NewRequest(http.MethodGet, "/ws", nil)
		req.Header.Set("Upgrade", upgradeVal)
		req.Header.Set("Connection", "Upgrade")
		w := httptest.NewRecorder()
		b.ServeHTTP(w, req)
		if w.Code != http.StatusNotImplemented {
			t.Errorf("Upgrade: %q → expected 501, got %d", upgradeVal, w.Code)
		}
	}
}

// HTTP backends must still forward WebSocket upgrades — regression guard.
func TestHTTP_WebSocket_NotRejected(t *testing.T) {
	upgraded := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			upgraded = true
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	b, _, _ := setupBackend(t, alaye.NewServer(server.URL), alaye.HealthCheck{}, alaye.CircuitBreaker{})
	defer b.Stop()

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	b.ServeHTTP(httptest.NewRecorder(), req)

	if !upgraded {
		t.Error("HTTP backend should forward WebSocket upgrade requests")
	}
}

// Circuit breaker and activity tracking

func TestFastCGI_CircuitBreaker(t *testing.T) {
	addr := startFastCGIServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	b := newFastCGIBackendForTest(t, "cgi://"+addr)
	b.Activity.Failures.Store(uint64(b.CBThreshold + 1))

	w := httptest.NewRecorder()
	b.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when circuit open on cgi:// backend, got %d", w.Code)
	}
}

func TestFastCGI_ActivityTracking(t *testing.T) {
	addr := startFastCGIServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	b := newFastCGIBackendForTest(t, "cgi://"+addr)
	b.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if b.Activity.Requests.Load() != 1 {
		t.Errorf("expected 1 request tracked, got %d", b.Activity.Requests.Load())
	}
	if b.Activity.InFlight.Load() != 0 {
		t.Error("in-flight should be 0 after request completes")
	}
	time.Sleep(10 * time.Millisecond)
	if snap := b.Activity.Latency.Snapshot(); snap.Count != 1 {
		t.Errorf("expected 1 latency sample, got %d", snap.Count)
	}
}

// Stop — idempotent, no nil-pointer panic when b.Proxy is nil

func TestFastCGI_Stop_NoPanic(t *testing.T) {
	addr := startFastCGIServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	b := newFastCGIBackendForTest(t, "cgi://"+addr)
	b.Stop()
	b.Stop() // idempotent
}

// Server helpers — IsFastCGI / FastCGINetwork / Validate

func TestServer_IsFastCGI(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"cgi://127.0.0.1:9001", true},
		{"cgi://unix:/var/run/app.sock", true},
		{"http://127.0.0.1:8080", false},
		{"https://127.0.0.1:8080", false},
		{"127.0.0.1:8080", false},
	}
	for _, c := range cases {
		s := alaye.NewServer(c.addr)
		if got := s.IsFastCGI(); got != c.want {
			t.Errorf("IsFastCGI(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestServer_FastCGINetwork(t *testing.T) {
	cases := []struct {
		addr    string
		network string
		address string
	}{
		{"cgi://127.0.0.1:9001", "tcp", "127.0.0.1:9001"},
		{"cgi://unix:/var/run/app.sock", "unix", "/var/run/app.sock"},
		{"http://127.0.0.1:8080", "", ""},
	}
	for _, c := range cases {
		s := alaye.NewServer(c.addr)
		n, a := s.FastCGINetwork()
		if n != c.network || a != c.address {
			t.Errorf("FastCGINetwork(%q) = (%q, %q), want (%q, %q)",
				c.addr, n, a, c.network, c.address)
		}
	}
}

func TestServer_Validate_FastCGI(t *testing.T) {
	cases := []struct {
		addr    string
		wantErr bool
	}{
		{"cgi://127.0.0.1:9001", false},
		{"cgi://unix:/var/run/app.sock", false},
		{"cgi://", true},
	}
	for _, c := range cases {
		s := alaye.NewServer(c.addr)
		err := s.Validate()
		if (err != nil) != c.wantErr {
			t.Errorf("Validate(%q): err=%v, wantErr=%v", c.addr, err, c.wantErr)
		}
	}
}

func TestFastCGI_SchemeConstant(t *testing.T) {
	if def.FastCGI != "cgi" {
		t.Errorf("def.FastCGI = %q, want %q", def.FastCGI, "cgi")
	}
}
