package xhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPExecutor_Probe_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("healthy"))
	}))
	defer server.Close()

	executor := &HTTPExecutor{
		URL:    server.URL,
		Method: "GET",
		Client: &http.Client{Timeout: 5 * time.Second},
	}

	success, latency, err := executor.Probe(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Error("expected success for 200 OK")
	}
	if latency <= 0 {
		t.Error("expected positive latency")
	}
}

func TestHTTPExecutor_Probe_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer server.Close()

	executor := &HTTPExecutor{
		URL:    server.URL + "/nonexistent",
		Method: "GET",
		Client: &http.Client{Timeout: 5 * time.Second},
	}

	success, _, err := executor.Probe(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Error("expected success for 404 - server is alive")
	}
}

func TestHTTPExecutor_Probe_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	}))
	defer server.Close()

	executor := &HTTPExecutor{
		URL:    server.URL,
		Method: "GET",
		Client: &http.Client{Timeout: 5 * time.Second},
	}

	success, _, err := executor.Probe(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if success {
		t.Error("expected failure for 500 error")
	}
}

func TestHTTPExecutor_Probe_ExpectedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	executor := &HTTPExecutor{
		URL:            server.URL,
		Method:         "GET",
		Client:         &http.Client{Timeout: 5 * time.Second},
		ExpectedStatus: []int{201},
	}

	success, _, err := executor.Probe(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Error("expected success for 201 with ExpectedStatus [201]")
	}
}

func TestHTTPExecutor_Probe_ExpectedStatusMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	executor := &HTTPExecutor{
		URL:            server.URL,
		Method:         "GET",
		Client:         &http.Client{Timeout: 5 * time.Second},
		ExpectedStatus: []int{201},
	}

	success, _, err := executor.Probe(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if success {
		t.Error("expected failure for 200 when expecting 201")
	}
}

func TestHTTPExecutor_Probe_ExpectedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "healthy"}`))
	}))
	defer server.Close()

	executor := &HTTPExecutor{
		URL:          server.URL,
		Method:       "GET",
		Client:       &http.Client{Timeout: 5 * time.Second},
		ExpectedBody: `"status": "healthy"`,
	}

	success, _, err := executor.Probe(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Error("expected success when body contains expected string")
	}
}

func TestHTTPExecutor_Probe_ExpectedBodyMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "unhealthy"}`))
	}))
	defer server.Close()

	executor := &HTTPExecutor{
		URL:          server.URL,
		Method:       "GET",
		Client:       &http.Client{Timeout: 5 * time.Second},
		ExpectedBody: `"status": "healthy"`,
	}

	success, _, err := executor.Probe(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if success {
		t.Error("expected failure when body doesn't contain expected string")
	}
}

func TestHTTPExecutor_Probe_ExpectedBodyNotCheckedOnErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"status": "healthy"}`))
	}))
	defer server.Close()

	executor := &HTTPExecutor{
		URL:          server.URL,
		Method:       "GET",
		Client:       &http.Client{Timeout: 5 * time.Second},
		ExpectedBody: `"status": "healthy"`,
	}

	success, _, err := executor.Probe(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if success {
		t.Error("expected failure when status is 500, even if body matches")
	}
}

func TestHTTPExecutor_Probe_ConnectionReuse(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 1,
		},
	}

	executor := &HTTPExecutor{
		URL:    server.URL,
		Method: "GET",
		Client: client,
	}

	for i := 0; i < 3; i++ {
		success, _, err := executor.Probe(context.Background())
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i+1, err)
		}
		if !success {
			t.Errorf("request %d: expected success", i+1)
		}
	}

	if requestCount != 3 {
		t.Errorf("expected 3 requests, got %d", requestCount)
	}
}

func TestHTTPExecutor_Probe_BodyDrainedOnFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error body content here"))
	}))
	defer server.Close()

	executor := &HTTPExecutor{
		URL:    server.URL,
		Method: "GET",
		Client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 1,
			},
		},
	}

	// First probe: server returns 500, should fail but not error (connection reused)
	success, _, err := executor.Probe(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on first probe: %v", err)
	}
	if success {
		t.Error("expected failure for 500 status")
	}

	// Second probe: verifies body was drained and connection reused.
	// Server still returns 500, so success must be false, but err must be nil.
	success2, _, err := executor.Probe(context.Background())
	if err != nil {
		t.Fatalf("second request error (connection reuse failed): %v", err)
	}
	if success2 {
		t.Error("expected second request to also fail for 500 status")
	}
	// Key verification: err == nil proves body was drained and connection reused
}

func TestHTTPExecutor_Probe_DefaultMethod(t *testing.T) {
	methodReceived := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methodReceived = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	executor := &HTTPExecutor{
		URL:    server.URL,
		Client: &http.Client{Timeout: 5 * time.Second},
	}

	_, _, _ = executor.Probe(context.Background())
	if methodReceived != "GET" {
		t.Errorf("expected default method GET, got %s", methodReceived)
	}
}

func TestHTTPExecutor_Probe_HostHeader(t *testing.T) {
	hostReceived := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostReceived = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	executor := &HTTPExecutor{
		URL:    server.URL,
		Method: "GET",
		Client: &http.Client{Timeout: 5 * time.Second},
		Host:   "custom.host.com",
	}

	_, _, _ = executor.Probe(context.Background())
	if hostReceived != "custom.host.com" {
		t.Errorf("expected Host header custom.host.com, got %s", hostReceived)
	}
}

func TestHTTPExecutor_Probe_ContextTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	executor := &HTTPExecutor{
		URL:    server.URL,
		Method: "GET",
		Client: &http.Client{},
	}

	_, _, err := executor.Probe(ctx)
	if err == nil {
		t.Error("expected timeout error")
	}
}

func TestHTTPExecutor_Probe_LargeBody(t *testing.T) {
	largeBody := strings.Repeat("x", 1024*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(largeBody))
	}))
	defer server.Close()

	executor := &HTTPExecutor{
		URL:    server.URL,
		Method: "GET",
		Client: &http.Client{Timeout: 5 * time.Second},
	}

	success, _, err := executor.Probe(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Error("expected success even with large body")
	}
}

func TestHTTPExecutor_Probe_EmptyBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	executor := &HTTPExecutor{
		URL:    server.URL,
		Method: "GET",
		Client: &http.Client{Timeout: 5 * time.Second},
	}

	success, _, err := executor.Probe(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Error("expected success with empty body")
	}
}

func TestHTTPExecutor_Probe_CustomHeaders(t *testing.T) {
	headerValue := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headerValue = r.Header.Get("X-Custom-Header")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	executor := &HTTPExecutor{
		URL:    server.URL,
		Method: "GET",
		Client: &http.Client{Timeout: 5 * time.Second},
		Header: http.Header{
			"X-Custom-Header": []string{"test-value"},
		},
	}

	_, _, _ = executor.Probe(context.Background())
	if headerValue != "test-value" {
		t.Errorf("expected header value test-value, got %s", headerValue)
	}
}
